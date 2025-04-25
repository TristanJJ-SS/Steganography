from PIL import Image
import binascii as t
import optparse

# Convert RGB to Hex
def rgb2hex(r, g, b):
    return '#{:02x}{:02x}{:02x}'.format(r, g, b)

# Convert Hex to RGB
def hex2rgb(hexcode):
    return tuple(map(int, bytes.fromhex(hexcode[1:])))

# Convert string to binary
def str2bin(message):
    return ''.join(format(ord(char), '08b') for char in message)

# Convert binary to string
def bin2str(binary):
    byte_array = [binary[i:i+8] for i in range(0, len(binary), 8)]
    
    try:
        message = ''.join([chr(int(byte, 2)) for byte in byte_array])
        return message
    except ValueError:
        return "Decoding error: Unable to convert binary to string."

# Encode message into hex
def encode(hexcode, digit):
    if hexcode[-1] in ('0', '1', '2', '3', '4', '5'):
        return hexcode[:-1] + digit
    return None

# Decode message from hex
def decode(hexcode):
    if hexcode[-1] in ('0', '1'):
        return hexcode[-1]
    return None

# Hide message in an image
def hide(filename, message):
    try:
        img = Image.open(filename)
    except Exception as e:
        return f"Error opening image: {e}"

    binary = str2bin(message) + '1111111111111110'  # End marker
    
    if img.mode not in ['RGBA', 'RGB']:
        img = img.convert('RGBA')

    if len(binary) > img.width * img.height:
        return "Image is too small to hold the message."

    datas = img.getdata()
    newdata = []
    digit = 0

    for item in datas:
        if digit < len(binary):
            newpix = encode(rgb2hex(item[0], item[1], item[2]), binary[digit])
            if newpix is None:
                newdata.append(item)
            else:
                r, g, b = hex2rgb(newpix)
                newdata.append((r, g, b, 255))
                digit += 1
        else:
            newdata.append(item)

    img.putdata(newdata)
    img.save(filename, "PNG")  # Ensure PNG format to avoid compression
    return "Message hidden successfully!"

# Retrieve hidden message from an image
def retr(filename):
    try:
        img = Image.open(filename)
    except Exception as e:
        return f"Error opening image: {e}"

    binary = ''
    
    if img.mode not in ['RGBA', 'RGB']:
        img = img.convert('RGBA')

    datas = img.getdata()
    for item in datas:
        digit = decode(rgb2hex(item[0], item[1], item[2]))
        if digit:
            binary += digit
            if binary[-16:] == '1111111111111110':  # End marker
                return bin2str(binary[:-16])  # Remove marker and decode

    return "No hidden message found."

# Main function
def main():
    parser = optparse.OptionParser('usage %prog ' + '-e/-d <target file>')
    parser.add_option('-e', dest='hide', type='string', help='Target image path to hide message')
    parser.add_option('-d', dest='retr', type='string', help='Target image path to retrieve message')
    (options, args) = parser.parse_args()

    if options.hide:
        filename = options.hide
        message = input("Enter the message to hide: ")
        print(hide(filename, message))
    elif options.retr:
        filename = options.retr
        print("Message successfully retrieved!")
        print("Decoded Message:", retr(filename))
    else:
        print("No option provided, use -e to hide or -d to retrieve.")

if __name__ == '__main__':
    main()
