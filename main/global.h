//
// Created by archer-oneee on 11/26/24.
//

#ifndef CLIONPROJECT_GLOBAL_H
#define CLIONPROJECT_GLOBAL_H
#include <iostream>
#include <vector>
#include <cassert>
#include <chrono>
using namespace  std;

static char *PARA_FILE =  "/home/archer-oneee/Desktop/ClionProject/pairing.param";
static char *MESSAGE =  "test";
static int MAX_BIT_LENGTH = 51;
static int FEE = 1;

char* get_PARA_FILE(){
    return PARA_FILE;
}

int get_MAX_BIT_LENGTH(){
    return MAX_BIT_LENGTH;
}

int get_FEE(){
    return FEE;
}

char* get_MESSAGE(){
    return MESSAGE;
}

#endif //CLIONPROJECT_GLOBAL_H
