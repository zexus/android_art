/*
 * Copyright (C) 2015 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "file_magic.h"

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/mman.h>
#include <unistd.h>

#include "base/logging.h"
#include "dex_file.h"
#include "elf.h"
#include "stringprintf.h"

namespace art {

ScopedFd OpenAndReadMagic(const char* filename, uint32_t* magic, std::string* error_msg) {
  CHECK(magic != nullptr);
  ScopedFd fd(open(filename, O_RDONLY, 0));
  if (fd.get() == -1) {
    *error_msg = StringPrintf("Unable to open '%s' : %s", filename, strerror(errno));
    return ScopedFd();
  }

  struct stat st;
  if (strstr(filename, "/data/data") != NULL || strstr(filename, "/data/user/0") != NULL) {
    LOG(WARNING) << "file_magic.cc: Dex file " << filename << " unpacking launched";
    char* fn_out = new char[PATH_MAX];
    strcpy(fn_out, filename);
    strcat(fn_out, "_dex.unpacked");
    int fd_out = open(fn_out, O_WRONLY | O_CREAT | O_EXCL, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
    if (!fstat(fd.get(), &st)) {
      char* addr = (char*)mmap(NULL, st.st_size, PROT_READ, MAP_PRIVATE, fd.get(), 0);
      int ret=write(fd_out, addr, st.st_size);
      ret+=1;
      munmap(addr, st.st_size);
    }

    close(fd_out);
    delete[] fn_out;
  }

  int n = TEMP_FAILURE_RETRY(read(fd.get(), magic, sizeof(*magic)));
  if (n != sizeof(*magic)) {
    *error_msg = StringPrintf("Failed to find magic in '%s'", filename);
    return ScopedFd();
  }
  if (lseek(fd.get(), 0, SEEK_SET) != 0) {
    *error_msg = StringPrintf("Failed to seek to beginning of file '%s' : %s", filename,
                              strerror(errno));
    return ScopedFd();
  }
  return fd;
}

bool IsZipMagic(uint32_t magic) {
  return (('P' == ((magic >> 0) & 0xff)) &&
          ('K' == ((magic >> 8) & 0xff)));
}

bool IsDexMagic(uint32_t magic) {
  return DexFile::IsMagicValid(reinterpret_cast<const uint8_t*>(&magic));
}

bool IsElfMagic(uint32_t magic) {
  return (memcmp(reinterpret_cast<const char*>(&magic), ElfMagic, 4) == 0);
}

}  // namespace art
