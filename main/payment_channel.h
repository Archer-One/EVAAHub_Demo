//
// Created by archer-oneee on 11/27/24.
//

#ifndef CLIONPROJECT_PAYMENT_CHANNEL_H
#define CLIONPROJECT_PAYMENT_CHANNEL_H
#include "PBC.h"
#include "tumbler.h"
#include "user.h"
#include "pairing_param.h"
#include "DBSign.h"

class PaymentChannel{
public:
    Tumbler* tumbler;
    User* user;
    int version;
    element_t user_blind_value;
    element_t Gt_user_blind_value;
    element_t tumbler_blind_value;
    element_t Gt_tumbler_blind_value;


    pub_param_t *pp;
    int fee = get_FEE();
    PaymentChannel(Tumbler* tumbler, User* user){
        this->tumbler = tumbler;
        this->user = user;
        this->pp = tumbler->pp;
        get_G1_element(this->pp, user_blind_value);
        get_G1_element(this->pp, tumbler_blind_value);
        get_Gt_element(this->pp, Gt_user_blind_value);
        get_Gt_element(this->pp, Gt_tumbler_blind_value);
        version = 0;
    }

    void open_phase(int version){
        user->init_blind_value();
        DBSign::cal_M(this->pp, user->value, user->payment_blind_values[version].user->r1, user->payment_blind_values[version].user->r2, user_blind_value);
        DBSign::cal_M(this->pp, tumbler->value, user->payment_blind_values[version].tumbler->r1, user->payment_blind_values[version].tumbler->r2, tumbler_blind_value);

    }

    puzzle_t puzzle_promise1(signed long tx_value){
        //only between receiver and tumbler
        assert(tx_value <= tumbler->value);
        puzzle_t response;

        // response.new_m = g1^{tx_value} h1^{k1} h2^{k2}
        Zr_random(pp, response.k1);
        response.tx_value = tx_value;
        DBSign::cal_M(this->pp, tx_value, response.k1, response.new_m);

        return response;

    }


    pair<puzzle_t, dz_proofs_t*> puzzle_promise2(puzzle_t puzzle){
        //only between sender and tumbler
        assert(puzzle.tx_value+fee <= user->value);

        // new_M = g1^{tx_value} h1^{k1} h2^{k2}
        Zr_random(pp, puzzle.k2);


        DBSign::cal_M(this->pp,  puzzle.k2, puzzle.new_m, puzzle.m);

        dz_msg_t *ba_msg = get_usr_msg();
        dz_msg_t *tx_msg = puzzle_2_msg(puzzle);


        dz_proofs_t* proofs = (dz_proofs_t *) malloc(sizeof(dz_proofs_t));
        DZKRP::prove(pp, ba_msg, tx_msg, get_MAX_BIT_LENGTH(), get_MESSAGE(), proofs);


//        int result = DZKRP::verify(pp, proofs, ba_msg->m, tx_msg->m, get_MESSAGE());

        return make_pair(puzzle, proofs);
    }

    db_sig_t * puzzle_solve1(puzzle_t puzzle, dz_proofs_t* proofs){
        // only between sender and tumbler
        element_t Gt_m, Gt_user_value;
        get_Gt_element(pp, Gt_m);
        get_Gt_element(pp, Gt_user_value);
        pairing_pp_apply(Gt_user_value, user_blind_value, pp->pp);
        pairing_pp_apply(Gt_m, puzzle.m, pp->pp);

        int result = DZKRP::verify(pp, proofs, Gt_user_value, Gt_m, get_MESSAGE());
        if (result==0){
            cout << "verify proof failed!" << endl;
        }
        db_sig_t *sig = (db_sig_t *)malloc(sizeof(db_sig_t));
        DBSign::sign(pp, puzzle.m, tumbler->key_pair->sk, sig);
        return sig;
    }

    db_sig_t * puzzle_solve2(puzzle_t puzzle, db_sig_t * sig){
        // only between sender and tumbler
        db_sig_t *new_sig = (db_sig_t *)malloc(sizeof(db_sig_t));

        int result = DBSign::verify(pp, sig, puzzle.m, tumbler->key_pair->G2_pk);
        if(result == 1){
            // update payment between sender and tumbler
            update_st_channel(puzzle);
        }

//        DBSign::ran_unblind(pp, sig, new_sig, puzzle.k2, puzzle.new_m);
//        DBSign::verify(pp, new_sig, puzzle.new_m, tumbler->key_pair->G2_pk);
        return sig;
    }

    db_sig_t * puzzle_solve3(puzzle_t puzzle, db_sig_t * sig){
        // only between receiver and tumbler
        db_sig_t *new_sig = (db_sig_t *)malloc(sizeof(db_sig_t));


        DBSign::ran_unblind(pp, sig, new_sig, puzzle.k2, puzzle.new_m);
        return new_sig;
    }

    void puzzle_solve4(puzzle_t puzzle, db_sig_t * new_sig){
        // only between receiver and tumbler

        int result = DBSign::verify(pp, new_sig, puzzle.new_m, tumbler->key_pair->G2_pk);

        if(result == 1){
            // update payment between sender and tumbler
            update_rt_channel(puzzle);
        }
        return;
    }




    dz_msg_t * puzzle_2_msg(puzzle_t puzzle){
        dz_msg_t *msg = (dz_msg_t *)malloc(sizeof(dz_msg_t));
        msg->x_v = puzzle.tx_value;

        get_Zr_element(pp, msg->x);
        get_Zr_element(pp, msg->r1);
        get_Zr_element(pp, msg->r2);
        get_Gt_element(pp, puzzle.Gt_m);

//        get_Gt_element(pp, msg->new_m);
        get_Gt_element(pp, msg->m);

        set_Zr_element_value(pp, msg->x, puzzle.tx_value);
        element_set(msg->r1, puzzle.k1);

        pairing_pp_apply(msg->m, puzzle.m, pp->pp);

        return msg;
    }

    void update_rt_channel(puzzle_t puzzle){
        element_t tx_value;
        set_Zr_element_value(pp, tx_value, puzzle.tx_value);

        // no fee here
        element_add(user_blind_value, user_blind_value, tx_value);

        element_sub(tumbler_blind_value, tumbler_blind_value, tx_value);

        blind_value_t * user_blind= (blind_value_t *)malloc(sizeof(blind_value_t));
        get_Zr_element(pp, user_blind->r1);
        get_Zr_element(pp, user_blind->r2);

        user->value += puzzle.tx_value;
        element_add(user_blind->r1, user->payment_blind_values[version].user->r1, puzzle.k1);
        element_add(user_blind->r2, user->payment_blind_values[version].user->r2, puzzle.k2);
        element_add(user_blind_value, user_blind_value, puzzle.m);


//        element_t m1;
//        DBSign::cal_M(pp, user->value, user_blind->r1, user_blind->r2, m1);
//        int result1 = element_cmp(m1 ,user_blind_value);

        blind_value_t * tumbler_blind= (blind_value_t *)malloc(sizeof(blind_value_t));
        get_Zr_element(pp, tumbler_blind->r1);
        get_Zr_element(pp, tumbler_blind->r2);

        tumbler->value -= puzzle.tx_value;
        element_sub(tumbler_blind->r1, user->payment_blind_values[version].tumbler->r1, puzzle.k1);
        element_sub(tumbler_blind->r2, user->payment_blind_values[version].tumbler->r2, puzzle.k2);
        element_sub(tumbler_blind_value, tumbler_blind_value, puzzle.m);

//        element_t m2;
//        DBSign::cal_M(pp, tumbler->value, tumbler_blind->r1, tumbler_blind->r2, m2);
//        int result2 = element_cmp(m2 ,tumbler_blind_value);

        payment_blind_t payment_blind;
        payment_blind.user = user_blind;
        payment_blind.tumbler = tumbler_blind;
        user->payment_blind_values.push_back(payment_blind);
        version += 1;
    }

    void update_st_channel(puzzle_t puzzle){
        element_t tx_value;
        set_Zr_element_value(pp, tx_value, puzzle.tx_value);

        // no fee here
        element_sub(user_blind_value, user_blind_value, tx_value);
        element_add(tumbler_blind_value, tumbler_blind_value, tx_value);

        blind_value_t * user_blind= (blind_value_t *)malloc(sizeof(blind_value_t));
        get_Zr_element(pp, user_blind->r1);
        get_Zr_element(pp, user_blind->r2);

        user->value -= puzzle.tx_value;
        element_sub(user_blind->r1, user->payment_blind_values[version].user->r1, puzzle.k1);
        element_sub(user_blind->r2, user->payment_blind_values[version].user->r2, puzzle.k2);
        element_sub(user_blind_value, user_blind_value, puzzle.m);


//        element_t m1;
//        DBSign::cal_M(pp, user->value, user_blind->r1, user_blind->r2, m1);
//        int result1 = element_cmp(m1 ,user_blind_value);

        blind_value_t * tumbler_blind= (blind_value_t *)malloc(sizeof(blind_value_t));
        get_Zr_element(pp, tumbler_blind->r1);
        get_Zr_element(pp, tumbler_blind->r2);

        tumbler->value += puzzle.tx_value;
        element_add(tumbler_blind->r1, user->payment_blind_values[version].tumbler->r1, puzzle.k1);
        element_add(tumbler_blind->r2, user->payment_blind_values[version].tumbler->r2, puzzle.k2);
        element_add(tumbler_blind_value, tumbler_blind_value, puzzle.m);

//        element_t m2;
//        DBSign::cal_M(pp, tumbler->value, tumbler_blind->r1, tumbler_blind->r2, m2);
//        int result2 = element_cmp(m2 ,tumbler_blind_value);

        payment_blind_t payment_blind;
        payment_blind.user = user_blind;
        payment_blind.tumbler = tumbler_blind;
        user->payment_blind_values.push_back(payment_blind);
        version += 1;
    }

    dz_msg_t * get_usr_msg(){

        dz_msg_t *msg = (dz_msg_t *)malloc(sizeof(dz_msg_t));
        msg->x_v = this->user->value;

        get_Zr_element(pp, msg->x);
        get_Zr_element(pp, msg->r1);
        get_Zr_element(pp, msg->r2);

        get_Gt_element(pp, msg->m);
        set_Zr_element_value(pp, msg->x, msg->x_v);

        element_set(msg->r1, this->user->payment_blind_values[version].user->r1);
        element_set(msg->r2, this->user->payment_blind_values[version].user->r2);

        pairing_pp_apply(msg->m, user_blind_value, pp->pp);
        return msg;
    }


};
#endif //CLIONPROJECT_PAYMENT_CHANNEL_H
