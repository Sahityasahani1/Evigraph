import json, sys
def peek(o, d=0):
    pad = "  " * d
    if isinstance(o, dict):
        for k, v in list(o.items())[:25]:
            if isinstance(v, (dict, list)) and d < 3:
                print(f"{pad}{k}: {type(v).__name__}({len(v)})"); peek(v, d + 1)
            else:
                print(f"{pad}{k}: {json.dumps(v)[:70]}")
    elif isinstance(o, list) and o:
        print(f"{pad}[0]:"); peek(o[0], d + 1)
for f in sys.argv[1:]:
    print("=====", f); peek(json.load(open(f, encoding="utf-8")))
