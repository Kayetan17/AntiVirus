import pefile


def extract_static_features(filepath):
    try:
        pe = pefile.PE(filepath)

        features = {
            "MinorOperatingSystemVersion": pe.OPTIONAL_HEADER.MinorOperatingSystemVersion,
            "MajorLinkerVersion": pe.OPTIONAL_HEADER.MajorLinkerVersion,
            "SizeOfStackReserve": pe.OPTIONAL_HEADER.SizeOfStackReserve,
            "MajorSubsystemVersion": pe.OPTIONAL_HEADER.MajorSubsystemVersion,
            "TimeDateStamp": pe.FILE_HEADER.TimeDateStamp,
            "ImageBase": pe.OPTIONAL_HEADER.ImageBase,
            "Characteristics": pe.FILE_HEADER.Characteristics,
            "MajorOperatingSystemVersion": pe.OPTIONAL_HEADER.MajorOperatingSystemVersion,
            "Subsystem": pe.OPTIONAL_HEADER.Subsystem,
            "MinorImageVersion": pe.OPTIONAL_HEADER.MinorImageVersion,
            "MinorSubsystemVersion": pe.OPTIONAL_HEADER.MinorSubsystemVersion,
            "DllCharacteristics": pe.OPTIONAL_HEADER.DllCharacteristics,
            "SizeOfInitializedData": pe.OPTIONAL_HEADER.SizeOfInitializedData,
            "MajorImageVersion": pe.OPTIONAL_HEADER.MajorImageVersion,
            "DirectoryEntryImportSize": (pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].Size if pe.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress != 0 else 0),
            "DirectoryEntryExport": (pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size if pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].VirtualAddress != 0 else 0),
            "AddressOfEntryPoint": pe.OPTIONAL_HEADER.AddressOfEntryPoint,
            "CheckSum": pe.OPTIONAL_HEADER.CheckSum
        }

        return features

    except Exception as e:
        print(f"Failed to extract from {filepath}: {e}")
        return None
