import pandas as pd
import pickle

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

# Sample malware-like features
malware_values = [[
    332, 224, 258, 9.0, 0.0, 51200, 10240, 0, 4096, 4096, 8192, 4194304,
    4096, 512, 6, 0, 0, 0, 6, 0, 131072, 1024, 0, 2, 0, 1048576, 4096, 1048576,
    4096, 0, 16, 5, 7.2, 6.8, 7.9, 10000, 2048, 20480, 25000, 18000, 1024,
    5, 30, 0, 0, 6, 6.9, 1.5, 7.9, 1024, 512, 4096, 72, 16
]]

# Create DataFrame
malware_df = pd.DataFrame(malware_values, columns=FEATURES)

# Load the trained model
with open("../assets/random_forest_model2.pkl", "rb") as f:
    model = pickle.load(f)

# Predict
prediction = model.predict(malware_df)
label = "Malware" if prediction[0] == 1 else "Benign"
print(f"Prediction: {label}")
