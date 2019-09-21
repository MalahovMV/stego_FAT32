import os

class Fat32:
    def __init__(self, fs_iso):
        self.fs_iso = fs_iso
        with open(self.fs_iso, "rb") as file:
            super_block = file.read(512)

        self.bytes_per_sec = (super_block[12]) * (16 ** 2) + super_block[11]
        self.sec_per_clus = super_block[13]
        self.rsvd_sec_cnt = (super_block[15]) * (16 ** 2) + super_block[14]
        self.num_FATs = super_block[16]
        self.toSec32 = (super_block[35]) * (16 ** 6) + (super_block[34]) * ( 16 ** 4) + (super_block[33]) * (16 ** 2) + super_block[32]
        self.FATsz32 = (super_block[39]) * (16 ** 6) + (super_block[38]) * ( 16 ** 4) + (super_block[37]) * (16 ** 2) + super_block[36]
        self.root_clus = (super_block[47]) * (16 ** 6) + (super_block[46]) * ( 16 ** 4) + (super_block[45]) * (16 ** 2) + super_block[44]

        self.fat_begin = self.rsvd_sec_cnt * self.bytes_per_sec
        self.root_dir = self.fat_begin + self.num_FATs * self.FATsz32 * self.bytes_per_sec

    def get_first_data_of_cluster(self, number_cluster):
        '''

        :param number_cluster:
        :return: addr of first data in cluster
        '''
        if number_cluster < self.root_clus:
            raise Exception('Bad number of cluster')

        first_data_of_cluster = (number_cluster - self.root_clus) * self.sec_per_clus * self.bytes_per_sec + self.root_dir
        return first_data_of_cluster

    def get_all_empty_cluster(self):
        self.list_empty_cluster = []
        with open(self.fs_iso, "rb") as file:
            file.seek(self.fat_begin)
            fat_table = file.read(self.FATsz32 * self.bytes_per_sec)

        for i in range((os.path.getsize(self.fs_iso) - self.root_dir) // self.bytes_per_sec // self.sec_per_clus + self.root_clus):
            if (fat_table[4*i] == 0) and (fat_table[4*i+1] == 0) and\
                (fat_table[4*i+2] == 0) and (fat_table[4*i+3] == 0):
                self.list_empty_cluster.append(i)


class File_for_stego():
    def __init__(self, name_file):
        self.file_name = name_file
        self.len_fields_size_of_files = 6
        self.len_fields_number_of_copies = 1
        self.len_fields_link_to_next = 4
        self.file_size = os.path.getsize(self.file_name)
        if self.file_size > 2**43: #8Гб
            raise Exception('Файл размером больше 8 Гб не может быть обработан')

    def cat_file(self, size_cluster, LEN_HEADERS_FIRST_BLOCKS, LEN_HEADERS):
        self.part_files = []
        already_processed = 0
        file = open(self.file_name, 'rb')
        data = file.read()
        file.close()
        while already_processed < len(data):
            if not already_processed:
                if len(data) - already_processed >= (size_cluster - LEN_HEADERS_FIRST_BLOCKS):
                    self.part_files.append(data[0:size_cluster - LEN_HEADERS_FIRST_BLOCKS ])
                else:
                    self.part_files.append(data[:])
                    while(len(self.part_files[-1])) < size_cluster - LEN_HEADERS_FIRST_BLOCKS :
                        self.part_files[-1] += b'\x00'

                already_processed += size_cluster - LEN_HEADERS_FIRST_BLOCKS

            else:
                if len(data) - already_processed >= (size_cluster - LEN_HEADERS):
                    self.part_files.append(data[already_processed:already_processed + size_cluster - LEN_HEADERS])
                else:
                    self.part_files.append(data[already_processed:])
                    while(len(self.part_files[-1])) < size_cluster - LEN_HEADERS:
                        self.part_files[-1] += b'\x00'

                already_processed += size_cluster - LEN_HEADERS