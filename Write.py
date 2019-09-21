import sys
import Universal_Function
import random
from Crypto.Cipher import ARC4
from Crypto.Cipher import AES
import mmap


KEY_SIZE = 16
LEN_MARKER = 16
LEN_HEADERS_FIRST_BLOCKS = 96
LEN_HEADERS = 64
LEN_STREAM_KEY = 256

def get_list_empty_cluster(fs, number_of_blocks):
    '''
    :param fs: FS iso
    :param number_of_blocks:
    :return: random empty blocks from FS
    '''
    fs.get_all_empty_cluster()
    if len(fs.list_empty_cluster) < number_of_blocks:
        raise Exception('В файловой системе недостаточно свободного места для хранения этого файла')

    random.shuffle(fs.list_empty_cluster)
    return fs.list_empty_cluster[:number_of_blocks]

def number_cluster_to_bin(number_cluster):
    '''

    :param number_cluster: number in int
    :return: number to byte string
    '''
    number_cluster_bin = b''
    while (number_cluster):
        number_cluster_bin += bytes(bytearray([number_cluster % 256]))
        number_cluster = number_cluster // 256

    while len(number_cluster_bin) < 4:
        number_cluster_bin = number_cluster_bin + b'\x00'

    return number_cluster_bin

def get_file_size(file):
    '''

    :param file:
    :return: file size in string bin
    '''
    file_size = b''
    file_size_int = file.file_size
    while (file_size_int):
        file_size += bytes(bytearray([file_size_int % 256]))
        file_size_int = file_size_int // 256

    while len(file_size) < 6:
        file_size = file_size + b'\x00'

    return file_size

def create_markers(key, number_copies):
    '''

    :param key:
    :param number_copies:
    :return: list of markers
    '''
    cipher = AES.new(key)
    str_for_encr = b''
    for i in range(number_copies):
        str_for_encr += key[:-1] + bytes(bytearray([i]))

    markers = cipher.encrypt(str_for_encr)
    marker_list = []
    while markers:
        marker_list.append(markers[:LEN_MARKER])
        markers = markers[LEN_MARKER:]

    return marker_list

def generate_stream_keys(key, marker_list):
    '''

    :param key:
    :param marker_list:
    :return: list of stream key

    '''
    stream_key_list = []
    cipher = AES.new(key[KEY_SIZE:KEY_SIZE*2])
    for el in marker_list:
        stream_key_list.append(cipher.encrypt(el+key))

    return stream_key_list

def generate_all_link_to_next_cluster(current_cluster, number_copies, list_empty_cluster):
    '''

    :param current_cluster:
    :param number_copies:
    :param list_empty_cluster:
    :return: link to next cluster, this create for header each clusters
    '''
    link_next_clusters = b''
    for i in range(number_copies):
        link_next_clusters += number_cluster_to_bin(list_empty_cluster[current_cluster*number_copies + i])

    return link_next_clusters

def cipher_data(obj_file, headers, current_copies, stream_keys, size_cluster):
    '''

    :param obj_file:
    :param headers:
    :param current_copies:
    :param stream_keys:
    :param size_cluster:
    :return: cipher data with using RC4
    '''
    data_with_headers = b''
    for i in range(len(obj_file.part_files)):
        data_with_headers += obj_file.part_files[i]

    cipher = ARC4.new(stream_keys[current_copies])
    data_with_headers = cipher.encrypt(data_with_headers)

    for i in range(len(obj_file.part_files)):
        data_with_headers = data_with_headers[:i*size_cluster] + headers[i + current_copies*len(obj_file.part_files)] + data_with_headers[i*size_cluster:]

    return data_with_headers


def generate_headers(markers, number_copies, obj_file, key, list_empty_cluster):
    '''

    :param markers:
    :param number_copies:
    :param obj_file:
    :param key:
    :param list_empty_cluster:
    :return: all headers for clusters
    '''
    headres = []
    cipher = AES.new(key)
    for j in range(number_copies):
        for i in range(len(obj_file.part_files)):
            if not i:
                if (i + 1) == len(obj_file.part_files):
                    header = get_file_size(obj_file) + bytes(bytearray([j])) + number_cluster_to_bin(
                        0) * number_copies

                else:
                    header = get_file_size(obj_file) + bytes(bytearray([j])) + generate_all_link_to_next_cluster(i, number_copies,
                                                                                         list_empty_cluster)

            elif (i + 1) == len(obj_file.part_files):
                header = bytes(bytearray([j])) + number_cluster_to_bin(0) * number_copies

            else:
                header = bytes(bytearray([j])) + generate_all_link_to_next_cluster(i, number_copies,
                                                                                                list_empty_cluster)
            while len(header) < LEN_HEADERS:
                header += b'\xFF'

            if len(header) % 16:
                raise Exception('Number of copies too much for this header length')

            header = cipher.encrypt(header)
            if not i:
                header = markers[j] + header
                while len(header) < LEN_HEADERS_FIRST_BLOCKS:
                    header += b'\xFF'


            headres.append(header)

    return headres

def prepapre_clusters_for_write(file_with_key, list_empty_cluster, obj_file, number_copies, size_cluster):
    '''

    :param file_with_key:
    :param list_empty_cluster:
    :param obj_file:
    :param number_copies:
    :param size_cluster:
    :return: all copies of file after cipher and added headers
    '''
    with open(file_with_key, 'rb') as file:
        key = file.read()
        if len(key) < LEN_STREAM_KEY - LEN_MARKER:
            raise Exception('Key too small')

        key = key[:LEN_STREAM_KEY - LEN_MARKER]

    markers = create_markers(key[:KEY_SIZE], number_copies)


    stream_keys = generate_stream_keys(key, markers)
    headers = generate_headers(markers, number_copies, obj_file, key[:KEY_SIZE], list_empty_cluster[number_copies:])
    data_copies = []
    for i in range(number_copies):
        data_with_headers = cipher_data(obj_file, headers, i, stream_keys, size_cluster)
        data_copies.append(data_with_headers)

    return data_copies


def main(file_to_stego, file_with_key, fs_iso, number_copies):
    fs = Universal_Function.Fat32(fs_iso)
    file = Universal_Function.File_for_stego(file_to_stego)
    file.cat_file(fs.bytes_per_sec*fs.sec_per_clus, LEN_HEADERS_FIRST_BLOCKS, LEN_HEADERS)
    list_empty_cluster_for_write = get_list_empty_cluster(fs, len(file.part_files)*number_copies)
    data_for_write = prepapre_clusters_for_write(file_with_key, list_empty_cluster_for_write, file, number_copies, fs.bytes_per_sec*fs.sec_per_clus)
    mmap_file = open(fs_iso, 'r+b')
    mmap_obj = mmap.mmap(mmap_file.fileno(), 0)
    j = 0
    while j < (len(list_empty_cluster_for_write)):
        for i in range(number_copies):
            mmap_obj[fs.root_dir + (list_empty_cluster_for_write[j] - fs.root_clus)*fs.sec_per_clus*fs.bytes_per_sec:\
                     fs.root_dir + (list_empty_cluster_for_write[j] - fs.root_clus + 1)*fs.sec_per_clus*fs.bytes_per_sec] = data_for_write[i][:fs.sec_per_clus*fs.bytes_per_sec]
            data_for_write[i] = data_for_write[i][fs.sec_per_clus*fs.bytes_per_sec:]
            j += 1

    mmap_obj.close()
    mmap_file.close()


if __name__ == '__main__':
    file_to_stego = sys.argv[1]
    file_with_key = sys.argv[2]
    fs_iso = sys.argv[3]
    number_copies = int(sys.argv[4])
    main(file_to_stego, file_with_key, fs_iso, number_copies)
