//
// Created by archer-oneee on 11/27/24.
//

#ifndef CLIONPROJECT_USER_H
#define CLIONPROJECT_USER_H
#include "global.h"
#include "PBC.h"
#include "pairing_param.h"
#include "struct_blind_payment.h"

class User{
public:
    signed long   value;
    pub_param_t * pp;
    vector<payment_blind_t> payment_blind_values;
    int cur_version;

    User(pub_param_t * pp, signed long  value){
        this->pp = pp;
        this->value = value;
        cur_version = 0;
    }

    void init_blind_value(){
        blind_value_t * user_blind= (blind_value_t *)malloc(sizeof(blind_value_t));

        Zr_random(pp, user_blind->r1);
        Zr_random(pp, user_blind->r2);

        blind_value_t * tumbler_blind= (blind_value_t *)malloc(sizeof(blind_value_t));
        Zr_random(pp, tumbler_blind->r1);
        Zr_random(pp, tumbler_blind->r2);
        payment_blind_t payment_blind;
        payment_blind.user = user_blind;
        payment_blind.tumbler = tumbler_blind;
        this->payment_blind_values.push_back(payment_blind);
    }




};
#endif //CLIONPROJECT_USER_H
