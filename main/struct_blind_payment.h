//
// Created by archer-oneee on 11/27/24.
//

#ifndef CLIONPROJECT_STRUCT_BLIND_PAYMENT_H
#define CLIONPROJECT_STRUCT_BLIND_PAYMENT_H
#include "PBC.h"
typedef struct{
    element_t r1;
    element_t r2;
} blind_value_t;

typedef struct{
    blind_value_t* user;
    blind_value_t* tumbler;
}payment_blind_t;

typedef struct{
    element_t m; // M = g1^{tx_value} h1^{k1} h2^{k2}
    element_t Gt_m; // Gt_M = e(M, g)
    element_t new_m; // new_M = g1^{tx_value} h1^{k1}
    element_t k1;
    element_t k2;
    signed long tx_value;
    element_t ele_tx;
}puzzle_t;



#endif //CLIONPROJECT_STRUCT_BLIND_PAYMENT_H
