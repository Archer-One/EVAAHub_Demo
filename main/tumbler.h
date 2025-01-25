//
// Created by archer-oneee on 11/27/24.
//

#ifndef CLIONPROJECT_TUMBLER_H
#define CLIONPROJECT_TUMBLER_H
#include "global.h"
#include "PBC.h"

class Tumbler{
public:
    signed long  value;
    pub_param_t * pp;
    db_keypair_t *key_pair;

    Tumbler(pub_param_t * pp, signed long  value){
        this->pp = pp;
        this->value = value;
        key_pair = (db_keypair_t *) malloc(sizeof(db_keypair_t));

        DBSign::key_gen(pp, key_pair);
    }
};
#endif //CLIONPROJECT_TUMBLER_H
