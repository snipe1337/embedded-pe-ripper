# embedded pe ripper

pulls embedded PE files out of a host binary. that's pretty much it.

useful if you're doing some pc checking and want to see what's hiding inside an executable, or just poking around during reverse engineering and notice a file is way bigger than it should be.

---

## what it does

scans a given `.exe` or `.dll` for any PE files (`.exe`, `.dll`, etc.) embedded inside it. when it finds one it dumps it out as `embedded_0.bin`, `embedded_1.bin`, and so on. skips the host PE itself so you're only getting the payloads.

---

## usage

```
python ripper.py <exe_or_dll>
```

example:

```
python ripper.py suspicious.exe
```

no dependencies outside of stdlib. just python 3.10+.

---

## showcase

<video src="https://github.com/user-attachments/assets/edbd85ef-684f-443a-9d15-22a3d0e3acec" controls width="100%"></video>

---

## notes

- starts scanning at offset `0x400` to skip past the host PE header
- validates MZ ? PE signature chain before dumping, so no false positives from random `MZ` bytes
- extracted files land in whatever directory you ran the script from

---

## made by

**ryze** � discord: `ryze.xzy`
server: [discord.gg/unimaginablev1](https://discord.gg/unimaginablev1)

[![Discord Presence](https://lanyard.cnrad.dev/api/1420036436505268244?theme=dark&bg=1a1a2e&borderRadius=10px&idleMessage=probably+cooking+something)](https://discord.com/users/1420036436505268244)
