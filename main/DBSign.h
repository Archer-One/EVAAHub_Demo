//
// Created by archer-oneee on 11/26/24.
//

#ifndef CLIONPROJECT_DBSIGN_H
#define CLIONPROJECT_DBSIGN_H

#include <stdio.h>
#include <stdlib.h>
#include "pairing_param.h"

typedef struct
{
    element_t sk;
    element_t G2_pk;
} db_keypair_t;

typedef struct
{
    element_t G1_sig0;
    element_t G2_sig1;
    element_t G1_sig2;
} db_sig_t;

typedef struct
{
    element_t x;
    element_t r1;
    element_t r2;
    element_t m;
    element_t new_m;
} db_msg_t;


void set_up(pub_param_t *pp)
{
    read_file(pp);
}

class DBSign{
public:
    static void key_gen(pub_param_t *pp, db_keypair_t *key_pair)
    {
        element_init_Zr(key_pair->sk, pp->pairing);
        element_init_G2(key_pair->G2_pk, pp->pairing);

        element_pp_pow_zn(key_pair->G2_pk, key_pair->sk, pp->G2_g_pp);

        // element_pow_zn(key_pair->G2_pk, pp->G2_g, key_pair->sk);
//        printf("key gen down!\n");
    }

    static void cal_M(pub_param_t *pp, db_msg_t *msg)
    {
        element_t g1_x;
        element_t h1_r1;
        element_t h2_r2;
        element_t temp1;

        get_G1_element(pp, g1_x);
        get_G1_element(pp, h1_r1);
        get_G1_element(pp, h2_r2);
        get_G1_element(pp, temp1);

        element_pp_pow_zn(g1_x, msg->x, pp->G1_g1_pp);

        element_pp_pow_zn(h1_r1, msg->r1, pp->G1_h1_pp);
        element_pp_pow_zn(h2_r2, msg->r2, pp->G1_h2_pp);

        element_add(msg->new_m, g1_x, h1_r1);
        element_add(msg->m, msg->new_m, h2_r2);
    }

    static void cal_M(pub_param_t *pp, signed long x_long, element_t r1, element_t m)
    {
        element_t x;
        set_Zr_element_value(pp, x, x_long);

        element_t g1_x;
        element_t h1_r1;
        element_t h2_r2;
        element_t temp1;

        get_G1_element(pp, g1_x);
        get_G1_element(pp, h1_r1);
        get_G1_element(pp, h2_r2);
        get_G1_element(pp, temp1);
        get_G1_element(pp, m);

        element_pp_pow_zn(g1_x, x, pp->G1_g1_pp);

        element_pp_pow_zn(h1_r1, r1, pp->G1_h1_pp);

        element_add(m, g1_x, h1_r1);
    }

    static void cal_M(pub_param_t *pp, element_t r2, element_t new_m, element_t m)
    {   // m = new_m * h2^{r2}

        element_t h2_r2;
        element_t temp1;


        get_G1_element(pp, h2_r2);
        get_G1_element(pp, temp1);
        get_G1_element(pp, m);

        element_pp_pow_zn(h2_r2, r2, pp->G1_h2_pp);

        element_add(m, new_m, h2_r2);


    }


    static void cal_M(pub_param_t *pp, signed long x_long, element_t r1, element_t r2, element_t m)
    {
        element_t x;
        set_Zr_element_value(pp, x, x_long);

        element_t g1_x;
        element_t h1_r1;
        element_t h2_r2;
        element_t temp1;
        element_t new_m;

        get_G1_element(pp, g1_x);
        get_G1_element(pp, h1_r1);
        get_G1_element(pp, h2_r2);
        get_G1_element(pp, temp1);
        get_G1_element(pp, new_m);
        get_G1_element(pp, m);

        element_pp_pow_zn(g1_x, x, pp->G1_g1_pp);

        element_pp_pow_zn(h1_r1, r1, pp->G1_h1_pp);
        element_pp_pow_zn(h2_r2, r2, pp->G1_h2_pp);

        element_add(new_m, g1_x, h1_r1);
        element_add(m, new_m, h2_r2);
    }


    static void sign(pub_param_t *pp, element_t M, element_t sk, db_sig_t *sig)
    {
        // M = g1^x h1^r1 h2^r2
        element_t g2_sk;
        element_t w;
        element_t M_w;

        get_G1_element(pp, g2_sk);
        get_G1_element(pp, M_w);
        get_Zr_element(pp, w);
        get_G1_element(pp, sig->G1_sig0);
        get_G2_element(pp, sig->G2_sig1);
        get_G1_element(pp, sig->G1_sig2);

        element_pp_pow_zn(g2_sk, sk, pp->G1_g2_pp);

        // element_pow_zn(g2_sk, pp->G1_g2, sk);
        element_random(w);
        element_pow_zn(M_w, M, w);
        element_add(sig->G1_sig0, g2_sk, M_w);

        element_pp_pow_zn(sig->G2_sig1, w, pp->G2_g_pp);
        element_pp_pow_zn(sig->G1_sig2, w, pp->G1_h2_pp);

        // element_pow_zn(sig->G2_sig1, pp->G2_g, w);
        // element_pow_zn(sig->G1_sig2, pp->G1_h2, w);
    }

    static int verify(pub_param_t *pp, db_sig_t *sig, element_t M, element_t pk)
    {
        element_t e_l;
        element_t e_r1;
        element_t e_r2;
        element_t e_r;
        get_Gt_element(pp, e_l);
        get_Gt_element(pp, e_r1);
        get_Gt_element(pp, e_r2);
        get_Gt_element(pp, e_r);

        element_pairing(e_l, sig->G1_sig0, pp->G2_g);
        element_pairing(e_r1, pp->G1_g2, pk);
        element_pairing(e_r2, M, sig->G2_sig1);
        element_add(e_r, e_r1, e_r2);

        if (!element_cmp(e_l, e_r))
        { // 比较temp1和temp2
//            printf("signature verify successfully!\n");
            return 1;
        }
        else
        {
//            printf("signature verify faild!\n");
            return 0;
        }
    }

    static void ran_unblind(pub_param_t *pp, db_sig_t *sig, db_sig_t *new_sig, db_msg_t *msg)
    {
        element_t d;
        element_t r2_neg;
        element_t wp;
        element_t temp1;
        element_t temp2;
        element_t temp3;

        get_G1_element(pp, new_sig->G1_sig0);
        get_G2_element(pp, new_sig->G2_sig1);
        get_G1_element(pp, new_sig->G1_sig2);

        get_G1_element(pp, d);
        get_G1_element(pp, temp1);
        get_G1_element(pp, temp2);
        get_G2_element(pp, temp3);
        get_Zr_element(pp, r2_neg);
        get_Zr_element(pp, wp);

        element_random(wp);

        element_neg(r2_neg, msg->r2);

        element_pow_zn(d, sig->G1_sig2, r2_neg); // d = h_2^{w \cdot -r2}

        element_add(temp1, sig->G1_sig0, d); // temp1 =

        element_pow_zn(temp2, msg->new_m, wp);

        element_add(new_sig->G1_sig0, temp1, temp2);

        element_pp_pow_zn(temp3, wp,pp->G2_g_pp);
        element_add(new_sig->G2_sig1, sig->G2_sig1, temp3);
    }

    static void ran_unblind(pub_param_t *pp, db_sig_t *sig, db_sig_t *new_sig, element_t r2, element_t new_m)
    {
        element_t d;
        element_t r2_neg;
        element_t wp;
        element_t temp1;
        element_t temp2;
        element_t temp3;

        get_G1_element(pp, new_sig->G1_sig0);
        get_G2_element(pp, new_sig->G2_sig1);
        get_G1_element(pp, new_sig->G1_sig2);

        get_G1_element(pp, d);
        get_G1_element(pp, temp1);
        get_G1_element(pp, temp2);
        get_G2_element(pp, temp3);
        get_Zr_element(pp, r2_neg);
        get_Zr_element(pp, wp);

        element_random(wp);

        element_neg(r2_neg, r2);

        element_pow_zn(d, sig->G1_sig2, r2_neg); // d = h_2^{w \cdot -r2}

        element_add(temp1, sig->G1_sig0, d); // temp1 =

        element_pow_zn(temp2, new_m, wp);

        element_add(new_sig->G1_sig0, temp1, temp2);

        element_pp_pow_zn(temp3, wp,pp->G2_g_pp);
        element_add(new_sig->G2_sig1, sig->G2_sig1, temp3);
    }
};


#endif //CLIONPROJECT_DBSIGN_H
