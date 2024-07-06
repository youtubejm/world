def reverse_ip_port_list(ip_port_list):
    return ip_port_list[::-1]

def write_ips_to_file(output_file, ip_port_list):
    with open(output_file, 'w') as file:
        for ip_port in ip_port_list:
            file.write(ip_port + '\n')

# Read IPs from the input file
input_file = 'f'
with open(input_file, 'r') as file:
    ip_port_addresses = [line.strip() for line in file]

# Reverse the order of IPs
reversed_ip_port_addresses = reverse_ip_port_list(ip_port_addresses)

# Write the reversed IPs to the output file
output_file = 'new.txt'
write_ips_to_file(output_file, reversed_ip_port_addresses)

print("Original IPs:", ip_port_addresses)
print("Reversed IPs:", reversed_ip_port_addresses)
print(f"Reversed IPs written to {output_file}")
