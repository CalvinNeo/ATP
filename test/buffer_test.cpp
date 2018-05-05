/*
*   Calvin Neo
*   Copyright (C) 2017  Calvin Neo <calvinneo@calvinneo.com>
*   https://github.com/CalvinNeo/ATP
*
*   This program is free software; you can redistribute it and/or modify
*   it under the terms of the GNU General Public License as published by
*   the Free Software Foundation; either version 2 of the License, or
*   (at your option) any later version.
*
*   This program is distributed in the hope that it will be useful,
*   but WITHOUT ANY WARRANTY; without even the implied warranty of
*   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
*   GNU General Public License for more details.
*
*   You should have received a copy of the GNU General Public License along
*   with this program; if not, write to the Free Software Foundation, Inc.,
*   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
*/
#include <cstdio>
#include <fstream>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <algorithm>
#include <functional>
#include <numeric>
#include <vector>

#include "scaffold.h"

using namespace std;

TBuffer<int> tbuf;

bool test(const std::vector<int> & vec, int offset){
    tbuf.clear();
    tbuf.init();
    std::string in, out;
    for(int i = 0; i < vec.size(); i++){
        printf("\nPut %u-th element %d + %d\n", i, vec[i], offset);
        tbuf.put(offset + vec[i], new int(vec[i]));
        in += ("," + std::to_string(vec[i]));
    }
    while(!tbuf.empty()){
        int * x = tbuf.front();
        tbuf.pop_front();
        out += ("," + std::to_string(*x));
        delete x;
    }
    for(int i = 0; i < vec.size(); i++){
        printf("\nPut %u-th element %d + %d\n", i, vec[i], offset);
        tbuf.put(offset + vec[i], new int(vec[i]));
        in += ("," + std::to_string(vec[i]));
    }
    while(!tbuf.empty()){
        int * x = tbuf.front();
        tbuf.pop_front();
        out += ("," + std::to_string(*x));
        delete x;
    }
    printf("I: %s\nO: %s\n", in.c_str(), out.c_str());
    return in == out;
}
int main(int argc, char* argv[], char* env[]){
    test({1,2,3}, 100);
    test({1,2,3,4,5,6,7,8,9,10}, 200);
    test({6,7,10,1,8,9,2,3,4,5}, 200);
    return 0;
}