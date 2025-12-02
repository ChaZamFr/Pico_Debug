# #!/usr/bin/zsh
#!/usr/bin/bash

for REG_FI in {0..12}; do
	echo "register R${REG_FI}"
	python new_new_gdb_python.py openocd.cfg ../build/matrix_mul.elf 10 100 20 "$REG_FI" 32 --timeout-us 5000000
done
