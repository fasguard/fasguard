#include <fstream>
#include <iostream>
#include <vector>
#include <stdint.h>

#define SIZE 3000000000

int
main(int argc, char *argv[])
{
  std::vector<uint8_t> vec;

  std::cout << "Sizeof uint_fast64_t: " << sizeof(uint_fast64_t) <<
    std::endl;

  std::vector<uint8_t>::size_type sz;
  std::cout << "Sizeof size_type: " << sizeof(sz) <<
    std::endl;

  vec.resize(SIZE,0);

  for(int i=0;i<SIZE;i++)
    {
      vec[i] = i;
    }

  std::ofstream binky("binky.bin",std::ios::out | std::ios::binary);

  std::vector<uint8_t>::iterator it = vec.begin();

  binky.write((char *)&vec[0],SIZE);

  binky.close();
}
