import pefile
import os
import traceback

FEATURES = [
    'Machine', 'SizeOfOptionalHeader', 'Characteristics', 'MajorLinkerVersion',
    'MinorLinkerVersion', 'SizeOfCode', 'SizeOfInitializedData', 'SizeOfUninitializedData',
    'AddressOfEntryPoint', 'BaseOfCode', 'BaseOfData', 'ImageBase', 'SectionAlignment',
    'FileAlignment', 'MajorOperatingSystemVersion', 'MinorOperatingSystemVersion',
    'MajorImageVersion', 'MinorImageVersion', 'MajorSubsystemVersion', 'MinorSubsystemVersion',
    'SizeOfImage', 'SizeOfHeaders', 'CheckSum', 'Subsystem', 'DllCharacteristics',
    'SizeOfStackReserve', 'SizeOfStackCommit', 'SizeOfHeapReserve', 'SizeOfHeapCommit',
    'LoaderFlags', 'NumberOfRvaAndSizes', 'SectionsNb', 'SectionsMeanEntropy',
    'SectionsMinEntropy', 'SectionsMaxEntropy', 'SectionsMeanRawsize', 'SectionsMinRawsize',
    'SectionMaxRawsize', 'SectionMaxVirtualsize', 'SectionsMeanVirtualsize', 'SectionsMinVirtualsize',
    'ImportsNbDLL', 'ImportsNb', 'ImportsNbOrdinal', 'ExportNb',
    'ResourcesNb', 'ResourcesMeanEntropy', 'ResourcesMinEntropy', 'ResourcesMaxEntropy',
    'ResourcesMeanSize', 'ResourcesMinSize', 'ResourcesMaxSize', 'LoadConfigurationSize',
    'VersionInformationSize'
]

def extract_exe_features(filepath):
    features = {feature: 0 for feature in FEATURES}

    if not os.path.exists(filepath):
        print(f"[ERROR] File not found: {filepath}")
        return None

    try:
        pe = pefile.PE(filepath)

        # FILE_HEADER
        features['Machine'] = pe.FILE_HEADER.Machine
        features['SizeOfOptionalHeader'] = pe.FILE_HEADER.SizeOfOptionalHeader
        features['Characteristics'] = pe.FILE_HEADER.Characteristics

        # OPTIONAL_HEADER
        if hasattr(pe, 'OPTIONAL_HEADER'):
            opt = pe.OPTIONAL_HEADER
            features.update({
                'MajorLinkerVersion': opt.MajorLinkerVersion,
                'MinorLinkerVersion': opt.MinorLinkerVersion,
                'SizeOfCode': opt.SizeOfCode,
                'SizeOfInitializedData': opt.SizeOfInitializedData,
                'SizeOfUninitializedData': opt.SizeOfUninitializedData,
                'AddressOfEntryPoint': opt.AddressOfEntryPoint,
                'BaseOfCode': opt.BaseOfCode,
                'ImageBase': opt.ImageBase,
                'SectionAlignment': opt.SectionAlignment,
                'FileAlignment': opt.FileAlignment,
                'MajorOperatingSystemVersion': opt.MajorOperatingSystemVersion,
                'MinorOperatingSystemVersion': opt.MinorOperatingSystemVersion,
                'MajorImageVersion': opt.MajorImageVersion,
                'MinorImageVersion': opt.MinorImageVersion,
                'MajorSubsystemVersion': opt.MajorSubsystemVersion,
                'MinorSubsystemVersion': opt.MinorSubsystemVersion,
                'SizeOfImage': opt.SizeOfImage,
                'SizeOfHeaders': opt.SizeOfHeaders,
                'CheckSum': opt.CheckSum,
                'Subsystem': opt.Subsystem,
                'DllCharacteristics': opt.DllCharacteristics,
                'SizeOfStackReserve': opt.SizeOfStackReserve,
                'SizeOfStackCommit': opt.SizeOfStackCommit,
                'SizeOfHeapReserve': opt.SizeOfHeapReserve,
                'SizeOfHeapCommit': opt.SizeOfHeapCommit,
                'LoaderFlags': opt.LoaderFlags,
                'NumberOfRvaAndSizes': opt.NumberOfRvaAndSizes
            })

            if hasattr(opt, 'BaseOfData'):
                features['BaseOfData'] = opt.BaseOfData

        # Sections
        if hasattr(pe, 'sections'):
            sections = pe.sections
            entropies = [s.get_entropy() for s in sections]
            raw_sizes = [s.SizeOfRawData for s in sections]
            virtual_sizes = [s.Misc_VirtualSize for s in sections]

            features['SectionsNb'] = len(sections)
            if sections:
                features['SectionsMeanEntropy'] = sum(entropies) / len(entropies)
                features['SectionsMinEntropy'] = min(entropies)
                features['SectionsMaxEntropy'] = max(entropies)

                features['SectionsMeanRawsize'] = sum(raw_sizes) / len(raw_sizes)
                features['SectionsMinRawsize'] = min(raw_sizes)
                features['SectionMaxRawsize'] = max(raw_sizes)

                features['SectionsMeanVirtualsize'] = sum(virtual_sizes) / len(virtual_sizes)
                features['SectionsMinVirtualsize'] = min(virtual_sizes)
                features['SectionMaxVirtualsize'] = max(virtual_sizes)

        # Imports
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            imports = pe.DIRECTORY_ENTRY_IMPORT
            features['ImportsNbDLL'] = len(imports)
            features['ImportsNb'] = sum(len(e.imports) for e in imports)
            features['ImportsNbOrdinal'] = sum(1 for e in imports for i in e.imports if i.ordinal is not None)

        # Exports
        if hasattr(pe, 'DIRECTORY_ENTRY_EXPORT') and hasattr(pe.DIRECTORY_ENTRY_EXPORT, 'symbols'):
            features['ExportNb'] = len(pe.DIRECTORY_ENTRY_EXPORT.symbols)

        # Resources
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE') and hasattr(pe.DIRECTORY_ENTRY_RESOURCE, 'entries'):
            features['ResourcesNb'] = len(pe.DIRECTORY_ENTRY_RESOURCE.entries)

            # Placeholder resource features
            features['ResourcesMeanEntropy'] = 0
            features['ResourcesMinEntropy'] = 0
            features['ResourcesMaxEntropy'] = 0
            features['ResourcesMeanSize'] = 0
            features['ResourcesMinSize'] = 0
            features['ResourcesMaxSize'] = 0

        # Load config
        if hasattr(pe, 'DIRECTORY_ENTRY_LOAD_CONFIG') and hasattr(pe.DIRECTORY_ENTRY_LOAD_CONFIG, 'struct'):
            features['LoadConfigurationSize'] = pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct.Size

        # Version info
        if hasattr(pe, 'VS_FIXEDFILEINFO') and pe.VS_FIXEDFILEINFO:
            features['VersionInformationSize'] = 1

    except Exception as e:
        print(f"[ERROR] Exception while parsing file: {e}")
        traceback.print_exc()
        return None

    return features


def main():
    filepath = './uploads/firefox.exe'  # Replace with your file path
    features = extract_exe_features(filepath)
    if features:
        print("Extracted Features:")
        for feature, value in features.items():
            print(f"{feature}: {value}")
    else:
        print("Failed to extract features.")

if __name__ == '__main__':
    main()