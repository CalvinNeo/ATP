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
#pragma once

#include <cstdlib>
#include <cstring>
#include <cstdio>
#include <vector>
#include <chrono>
#include <map>
#include <cstdarg>
#include <iostream>

template <typename T>
struct SizableCircularBuffer {
    // This is the mask. Since it's always a power of 2, adding 1 to this value will return the size.
    typedef std::pair<size_t, T> _Item;
    std::vector<_Item> elements;
    size_t oldest_index = 0;
    typedef _Item value_type;

    typename std::vector<_Item>::iterator begin() { return elements.begin(); }
    typename std::vector<_Item>::iterator end() { return elements.end(); }
    typename std::vector<_Item>::const_iterator begin() const { return elements.begin(); }
    typename std::vector<_Item>::const_iterator end() const  { return elements.end(); }

    SizableCircularBuffer(){

    }
    SizableCircularBuffer(size_t atleast_size){
        grow(atleast_size);
    }
    T get(size_t i) const { 
        return elements[i % size()].second; 
    }
    void put(size_t i, T data) { 

    }
    void raw_put(size_t i, T data){
        elements[i % size()] = std::make_pair(i, data);
    }
    void grow(size_t atleast_size){
        // Figure out the new size.
        // let x === a (mod 2^m),
        // need calculate b that x === b (mod 2^(m+1)), and we don't know x now.
        if((atleast_size & (atleast_size - 1)) != 0){
            size_t size = 1;
            do size *= 2; while (atleast_size > size);
            atleast_size = size;
        }

        elements.resize(atleast_size, _Item{});

    }
    void ensure_size(size_t atleast_size) { 
        if (atleast_size > size()) 
            grow(atleast_size); 
    }
    size_t size() const { 
        return elements.size(); 
    }
};


inline uint64_t get_current_ms(){
    using namespace std::chrono;
    time_point<system_clock, milliseconds> timepoint_now = time_point_cast<milliseconds>(system_clock::now());;
    auto tmp = duration_cast<milliseconds>(timepoint_now.time_since_epoch());  
    std::time_t timestamp = tmp.count();  
    return (uint64_t)timestamp;  
}

