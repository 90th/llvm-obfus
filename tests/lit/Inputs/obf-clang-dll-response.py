import pathlib
import runpy
import subprocess
import sys


def check_tokenizer(wrapper):
    split = runpy.run_path(wrapper)["_split_windows_linker_arguments"]
    assert split('"" "a b" x\ty') == ["", "a b", "x", "y"]
    assert split(r'/OUT:C:\work\library.dll') == [r'/OUT:C:\work\library.dll']
    assert split(r'"a""b"') == ['a"b']
    assert split('"unterminated') == ["unterminated"]
    for count in range(1, 7):
        argument = "prefix" + "\\" * count + '"' + "suffix"
        expected = "prefix" + "\\" * (count // 2) + ('"' if count % 2 else "") + "suffix"
        assert split(argument) == [expected], (argument, split(argument), expected)
        quoted = '"' + "prefix" + "\\" * count + '"' + "suffix"
        assert split(quoted) == [expected], (quoted, split(quoted), expected)
    print("DLL_RESPONSE_QUOTING_OK")


def make_response(output, response):
    output = pathlib.Path(output).resolve()
    response = pathlib.Path(response).resolve()
    nested = response.with_suffix(".nested.rsp")
    parent = str(output.parent)
    if any(char.isspace() for char in parent):
        parent = '"' + parent + '"'
    filename = subprocess.list2cmdline([output.name])
    # Keep the final path separator outside quotes, including paths with spaces.
    output_option = "/OUT:" + parent + "\\" + filename
    nested.write_text("/DLL\n/BASE:0x180000000\n/DYNAMICBASE\n/FIXED:NO\n" + output_option + "\n", encoding="utf-16")
    response.write_text(subprocess.list2cmdline(["@" + str(nested)]) + "\n", encoding="utf-8-sig")


if sys.argv[1] == "--check-tokenizer":
    check_tokenizer(sys.argv[2])
else:
    make_response(sys.argv[1], sys.argv[2])
