import sys
import struct
import os


class Logger:
    class _Color:
        Reset   = "\033[0m"
        Bold    = "\033[1m"
        Red     = "\033[1;31m"
        Green   = "\033[1;32m"
        Yellow  = "\033[1;33m"
        Cyan    = "\033[1;36m"
        Magenta = "\033[1;35m"
        Grey    = "\033[0;90m"

    _C = _Color

    @classmethod
    def Info(cls, Message: str) -> None:
        print(f"{cls._C.Cyan}  ·  {Message}{cls._C.Reset}")

    @classmethod
    def Good(cls, Message: str) -> None:
        print(f"{cls._C.Green}  ✓  {Message}{cls._C.Reset}")

    @classmethod
    def Warn(cls, Message: str) -> None:
        print(f"{cls._C.Yellow}  ⚠  {Message}{cls._C.Reset}")

    @classmethod
    def Error(cls, Message: str) -> None:
        print(f"{cls._C.Red}  ✗  {Message}{cls._C.Reset}")

    @classmethod
    def Dim(cls, Message: str) -> None:
        print(f"{cls._C.Grey}     {Message}{cls._C.Reset}")

    @classmethod
    def Banner(cls) -> None:
        Line = "─" * 45
        print(f"\n{cls._C.Magenta}{cls._C.Bold}")
        print(f"  {Line}")
        print(f"       embedded pe ripper  ·  by ryze")
        print(f"   pull embedded pe files out of host files")
        print(f"  {Line}")
        print(f"{cls._C.Reset}")

    @classmethod
    def Usage(cls, ScriptName: str) -> None:
        print(f"{cls._C.Grey}  usage: python {ScriptName} <exe_or_dll>{cls._C.Reset}")


MZ_MAGIC = b"MZ"
PE_MAGIC = b"PE\x00\x00"


def U16(Data: bytes, Offset: int) -> int:
    return struct.unpack_from("<H", Data, Offset)[0]


def U32(Data: bytes, Offset: int) -> int:
    return struct.unpack_from("<I", Data, Offset)[0]


class PeInspector:

    def __init__(self, Data: bytes) -> None:
        self.Data = Data
        self.Size = len(Data)

    def IsValidPe(self, MzOffset: int) -> bool:
        try:
            if self.Data[MzOffset:MzOffset + 2] != MZ_MAGIC:
                return False
            ELfanew  = U32(self.Data, MzOffset + 0x3C)
            PeOffset = MzOffset + ELfanew
            if PeOffset <= MzOffset or PeOffset + 4 > self.Size:
                return False
            return self.Data[PeOffset:PeOffset + 4] == PE_MAGIC
        except Exception:
            return False

    def GetPeFileSize(self, MzOffset: int) -> int | None:
        try:
            ELfanew      = U32(self.Data, MzOffset + 0x3C)
            PeOffset     = MzOffset + ELfanew
            NumSections  = U16(self.Data, PeOffset + 6)
            OptSize      = U16(self.Data, PeOffset + 20)
            SectionTable = PeOffset + 24 + OptSize
            MaxEnd = 0
            for Idx in range(NumSections):
                SecBase = SectionTable + Idx * 40
                RawSize = U32(self.Data, SecBase + 16)
                RawPtr  = U32(self.Data, SecBase + 20)
                if RawSize == 0:
                    continue
                End = RawPtr + RawSize
                if End > MaxEnd:
                    MaxEnd = End
            if MaxEnd == 0 or MaxEnd > self.Size:
                return None
            return MaxEnd
        except Exception:
            return None


class PeExtractor:
    ScanStartOffset = 0x400
    MinTailRoom     = 0x200

    def __init__(self, FilePath: str) -> None:
        self.FilePath = FilePath

    def Run(self) -> None:
        if not os.path.exists(self.FilePath):
            Logger.Error(f"file not found → {self.FilePath}")
            return

        Logger.Info(f"scanning  {self.FilePath}")

        with open(self.FilePath, "rb") as FileHandle:
            Data = FileHandle.read()

        Inspector = PeInspector(Data)
        Dumped    = []
        Found     = 0
        Cursor    = self.ScanStartOffset

        while Cursor < Inspector.Size - self.MinTailRoom:
            if Data[Cursor:Cursor + 2] == MZ_MAGIC and Inspector.IsValidPe(Cursor):
                PeSize = Inspector.GetPeFileSize(Cursor)

                if not PeSize:
                    Cursor += 2
                    continue

                if Cursor == 0:
                    Cursor += 2
                    continue

                if any(Start <= Cursor < End for Start, End in Dumped):
                    Cursor += 2
                    continue

                OutName = f"embedded_{Found}.bin"
                with open(OutName, "wb") as OutFile:
                    OutFile.write(Data[Cursor:Cursor + PeSize])

                Dumped.append((Cursor, Cursor + PeSize))
                Logger.Good(
                    f"extracted pe @ {hex(Cursor)}  "
                    f"size={hex(PeSize)}  →  {OutName}"
                )
                Logger.Dim(f"range [{hex(Cursor)} – {hex(Cursor + PeSize)}]")
                Found  += 1
                Cursor += PeSize
            else:
                Cursor += 1

        print()
        if Found == 0:
            Logger.Warn("nothing embedded in there — clean file")
        else:
            Logger.Good(f"all done  ·  pulled {Found} pe file(s)")


if __name__ == "__main__":
    Logger.Banner()

    if len(sys.argv) != 2:
        Logger.Error("wrong number of arguments")
        Logger.Usage(sys.argv[0])
        sys.exit(1)

    PeExtractor(sys.argv[1]).Run()
