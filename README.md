# GDB Debugger Steps


```bash
git clone https://github.com/raspberrypi/pico-sdk.git
cd pico-sdk
git submodule update --init --recursive
```

```bash
echo 'export PICO_SDK_PATH=~/pico/pico-sdk' >> ~/.zshrc
source ~/.zshrc
```

```bash
cd ..
mkdir build
cd build
cmake ..
make
```

```bash
python new_gdb_python.py openocd.cfg ../build/matrix_mul.elf <NUM_OF_INST> <RUN_LENGTH> <NUM_RUNS> <TARGET_REGISTER> <REG_LEN> --timeout-us <TIME IN μs>
```
```bash
# FOR EG:
python new_gdb_python.py openocd.cfg ../build/matrix_mul.elf 10 100 20 4 32 --timeout-us 10000000 # (10 SECS)
``` 

