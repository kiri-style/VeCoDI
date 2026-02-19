# CMSIS_NN

## Purpose
Local copy of CMSIS-NN headers/sources used by the split-inference pipeline.

## Contents
- `Include/`: CMSIS-NN public headers
- `Source/`: CMSIS-NN kernel implementations
- `CMakeLists.txt`: build glue for this folder

## Notes
This is vendor/third-party code mirrored locally for deterministic builds. Avoid editing unless you are intentionally updating CMSIS-NN.

## Used By
The split-inference implementation in [src/split_inference.cpp](src/split_inference.cpp) uses CMSIS-NN kernels for conv, add, pooling, and FC layers.