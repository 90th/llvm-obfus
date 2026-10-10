"""Check linker-selected implementations through VM callers in native ELF images."""
import argparse
import json
import os
from pathlib import Path
import shutil

from report_contract import coverage_contract
from vm_incoming_abi import run_process

TARGET = r'''
#include <stdint.h>
#ifndef VISIBILITY
#define VISIBILITY "default"
#endif
#ifndef LINKAGE
#define LINKAGE
#endif
LINKAGE __attribute__((noinline,visibility(VISIBILITY)))
uint64_t resolution_target(uint64_t x, uint64_t *effect) {
  uint64_t result = x * 7 + 101;
  *effect += result ^ 0x1234;
  return result;
}
__attribute__((noinline,visibility("default")))
uint64_t resolution_forward(uint64_t x, uint64_t *effect) {
  return resolution_target(x, effect);
}
'''
PROVIDER = r'''
#include <stdint.h>
__attribute__((noinline,visibility("default")))
uint64_t resolution_target(uint64_t x, uint64_t *effect) {
  uint64_t result = x * 11 + 303;
  *effect += result ^ 0x5678;
  return result;
}
'''
CONSUMER = r'''
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <inttypes.h>
typedef uint64_t (*calculate_fn)(uint64_t,uint64_t*);
__attribute__((noinline)) uint64_t resolution_callback(calculate_fn fn, uint64_t x, uint64_t *effect) {
  return fn(x,effect);
}
int main(int argc,char **argv) {
  if(argc!=4) return 20;
  void *provider=dlopen(argv[1],RTLD_NOW|RTLD_GLOBAL);
  void *target=dlopen(argv[2],RTLD_NOW|RTLD_LOCAL);
  if(!provider||!target) {fprintf(stderr,"%s\n",dlerror());return 21;}
  calculate_fn selected=(calculate_fn)dlsym(RTLD_DEFAULT,"resolution_target");
  calculate_fn forward=(calculate_fn)dlsym(target,"resolution_forward");
  if(!selected||!forward) return 22;
  unsigned own=(unsigned)strtoul(argv[3],NULL,10);
  uint64_t inputs[]={0,19,0x8000000000000000ULL,0xffffffffffffffffULL,0x8123456789abcdefULL};
  uint64_t actual_effects[3]={0},expected_effects[3]={0};
  for(unsigned repeat=0;repeat<8;++repeat) {
    for(unsigned i=0;i<sizeof(inputs)/sizeof(inputs[0]);++i) {
      uint64_t x=inputs[i]+repeat;
      uint64_t expected_selected=x*11+303;
      uint64_t expected_forward=own ? x*7+101 : expected_selected;
      uint64_t results[3]={selected(x,&actual_effects[0]),forward(x,&actual_effects[1]),
          resolution_callback(forward,x,&actual_effects[2])};
      uint64_t expected[3]={expected_selected,expected_forward,expected_forward};
      for(unsigned path=0;path<3;++path) {
        expected_effects[path]+=expected[path]^((path && own) ? 0x1234 : 0x5678);
        if(results[path]!=expected[path] || actual_effects[path]!=expected_effects[path]) {
          fprintf(stderr,"winner/effect mismatch repeat=%u input=%u path=%u actual=%"PRIu64" expected=%"PRIu64" effect=%"PRIu64" expected_effect=%"PRIu64"\n",
              repeat,i,path,results[path],expected[path],actual_effects[path],expected_effects[path]);
          return 1;
        }
      }
    }
  }
  selected=NULL;forward=NULL;
  if(dlclose(target)!=0 || dlclose(provider)!=0) return 23;
  puts("{\"ok\":true,\"exact_returns\":120,\"exact_effects\":120}");
  return 0;
}
'''


def require(condition, message):
    if not condition:
        raise AssertionError(message)


class Harness:
    def __init__(self, args):
        self.args=args
        self.work=args.work
        self.commands=[]
        self.rows=[]
        self.work.mkdir(parents=True,exist_ok=True)
        for name,source in (("target.c",TARGET),("provider.c",PROVIDER),("consumer.c",CONSUMER)):
            (self.work/name).write_text(source)

    def run(self, command, *, report=None):
        command=[str(item) for item in command]
        env={key:value for key,value in os.environ.items() if not key.upper().startswith("OBF") and
             key not in {"LD_PRELOAD","LD_AUDIT","LD_DEBUG","LD_DEBUG_OUTPUT"}}
        if report:
            env["OBF_COVERAGE_REPORT"]=str(report)
        result=run_process(command,cwd=self.work,env=env,timeout=300)
        self.commands.append(dict(command=command,exit=result.returncode,stdout=result.stdout,stderr=result.stderr))
        (self.work/"commands.json").write_text(json.dumps(self.commands,indent=2)+"\n")
        require(result.returncode==0,f"command failed: {command!r}\n{result.stdout}\n{result.stderr}")
        return result

    def matrix(self):
        clang=self.args.clang
        for linker in ("bfd","lld"):
            lookup=self.run([clang,f"-print-prog-name=ld.{linker}"]).stdout.strip()
            spelling=str(Path(lookup).absolute()) if Path(lookup).is_file() else shutil.which(lookup)
            if spelling is None and linker=="bfd":
                continue
            require(spelling is not None,f"native linker unavailable: ld.{linker}")
            link=[f"-fuse-ld={spelling}"]
            for optimization in (0,2):
                folder=self.work/f"{linker}-o{optimization}"
                folder.mkdir(exist_ok=True)
                flags=["-std=c11",f"-O{optimization}","-fno-inline","-g"]
                provider=folder/"provider.so"
                consumer=folder/"consumer"
                self.run([clang,*flags,"-fPIC","-shared",*link,self.work/"provider.c","-o",provider])
                self.run([clang,*flags,*link,self.work/"consumer.c","-ldl","-o",consumer])
                for kind,extra,own in (("weak",["-DLINKAGE=__attribute__((weak))"],False),
                                       ("default",[],False),
                                       ("hidden",['-DVISIBILITY="hidden"'],True),
                                       ("protected",['-DVISIBILITY="protected"'],True)):
                    raw=folder/f"raw-{kind}.so"
                    self.run([clang,*flags,"-fPIC",*extra,"-shared",*link,self.work/"target.c","-o",raw])
                    self.run([consumer,provider,raw,int(own)])
                    for level in ("vm","strong_vm"):
                        policy=folder/f"{level}.yaml"
                        policy.write_text("seed: 8675309\ndefault_level: none\ntargets:\n  - match: resolution_target\n    level: "+level+"\nvm:\n  max_mba_depth: 0\nself_checksum:\n  enabled: false\nsecurity:\n  fail_on_public_obf_symbol: true\n")
                        driver=[self.args.wrapper,f"--obf-config={policy}"]
                        for reports in (True,False):
                            stem=f"{kind}-{level}-reports-{'on' if reports else 'off'}"
                            obj=folder/f"{stem}.o"
                            binary=folder/f"{stem}.so"
                            report=folder/f"{stem}.json" if reports else None
                            self.run([*driver,*flags,"-fPIC",*extra,"-c",self.work/"target.c","-o",obj],report=report)
                            if report:
                                data=coverage_contract(json.loads(report.read_text()))
                                require(any(event["owner"]=="resolution_target" and event["mechanism"]=="vm" and
                                            event["status"]=="emitted" and event["scope"]=="whole_function"
                                            for event in data["emission"]),"selected target lost whole-function VM emission")
                            self.run([*driver,*flags,"-shared",*link,obj,"-o",binary])
                            native=json.loads(self.run([consumer,provider,binary,int(own)]).stdout)
                            self.rows.append(dict(linker=linker,optimization=optimization,kind=kind,level=level,
                                                  reports=reports,consumer=str(consumer),provider=str(provider),
                                                  binary=str(binary),native=native,compiler_report=str(report) if report else None))
                            (self.work/"result.json").write_text(json.dumps(dict(status="running",rows=self.rows),indent=2)+"\n")
        result=dict(status="passed",rows=self.rows,protected_cases=len(self.rows),
                    exact_returns=sum(row["native"]["exact_returns"] for row in self.rows),
                    exact_effects=sum(row["native"]["exact_effects"] for row in self.rows),
                    compiler_evidence="VM emission only; native VM execution requires independent debugger proof")
        (self.work/"result.json").write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps(result))


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--wrapper",required=True)
    parser.add_argument("--clang",required=True)
    parser.add_argument("--work",type=Path,required=True)
    args=parser.parse_args()
    args.work=args.work.absolute()
    Harness(args).matrix()


if __name__=="__main__":
    main()
