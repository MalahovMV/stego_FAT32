import sys
import Universal_Function
import Write
from Crypto.Cipher import AES
from Crypto.Cipher import ARC4

KEY_SIZE = 16
LEN_MARKER = 16
LEN_HEADERS_FIRST_BLOCKS = 96
LEN_HEADERS = 64
LEN_STREAM_KEY = 256


def bin_addr_to_int(bin_str):
    return bin_str[3] * (16**6) + bin_str[2] * (16**4) + bin_str[1] * (16**2) + bin_str[0]

def bin_size_to_int(bin_str):
    '''
    bin str to int
    :param bin_str:
    :return:
    '''
    size = 0
    for i in range(len(bin_str)):
        size += bin_str[i] * (16 ** (2*i))

    return size

def get_clusters(data, number_copies):
    '''

    :param data:
    :param number_copies:
    :return: addr of all clusters, that were listed in header
    '''
    list_clusters = []
    for i in range(number_copies):
        if data[:3] == b'\xFF\xFF\xFF':
            break

        else:
            list_clusters.append(bin_addr_to_int(data[:4]))
            data = data[4:]

    return list_clusters, number_copies


def decrypt_header(header, key):
    cipher = AES.new(key)
    return cipher.decrypt(header)

def main(file_with_key, fs_iso, number_copies):
    fs = Universal_Function.Fat32(fs_iso)
    with open(file_with_key, 'rb') as file:
        key = file.read(LEN_STREAM_KEY - LEN_MARKER)

    markers = Write.create_markers(key[:KEY_SIZE], number_copies)

    flag = 0
    with open(fs_iso, 'rb') as file:
        file.seek(fs.root_dir)
        while file:
            data = file.read(fs.sec_per_clus*fs.bytes_per_sec)
            for marker in markers:
                if marker == data[:LEN_MARKER]:
                    flag = 1
                    break

            if flag:
                break

        if flag:
            encr_data = []
            header = decrypt_header(data[LEN_MARKER:LEN_HEADERS_FIRST_BLOCKS], key[:KEY_SIZE])
            size = bin_size_to_int(header[:6])
            current_copies = header[6]
            encr_data.append({current_copies : data[LEN_HEADERS_FIRST_BLOCKS:]})
            next_clusters, number_copies = get_clusters(header[7:], number_copies)
            flag = 1
            while flag:
                flag = 0
                for cluster in next_clusters:
                    if not cluster:
                        continue

                    file.seek(fs.get_first_data_of_cluster(cluster))
                    data = (file.read(fs.sec_per_clus*fs.bytes_per_sec))
                    header = decrypt_header(data[:LEN_HEADERS], key[:KEY_SIZE])
                    if header[0] != next_clusters.index(cluster):
                        continue

                    if header[-3:] != b'\xFF\xFF\xFF':
                        continue

                    current_copies = header[0]
                    next_clusters, number_copies = get_clusters(header[1:], number_copies)
                    encr_data.append({current_copies : data[LEN_HEADERS:]})
                    flag = 1
                    break

            data = b''
            data_rows = []
            for i in range(number_copies):
                data_rows.append(data)

            for el in encr_data:
                for keys in el:
                    for i in range(number_copies):
                        if i == keys:
                            data_rows[keys] += el[keys]

                        else:
                            data_rows[i] += b'\x00'*len(el[keys])

            stream_keys = Write.generate_stream_keys(key, markers)
            for i in range(number_copies):
                cipher = ARC4.new(stream_keys[i])
                data_rows[i] = cipher.decrypt(data_rows[i])

            bin_data = b''
            for i in range(len(encr_data)):
                for keys in encr_data[i]:
                    bin_data += data_rows[keys][len(bin_data):len(bin_data)+len(encr_data[i][keys])]

            with open('Read', 'wb') as file_w:
                file_w.write(bin_data[:size])

        else:
            print('Not Stego information')


if __name__ == '__main__':
    file_with_key = sys.argv[1]
    fs_iso = sys.argv[2]
    number_copies = int(sys.argv[3])
    main(file_with_key, fs_iso, number_copies)