//
// Created by archer-oneee on 11/26/24.
//

#ifndef CLIONPROJECT_DZKRP_H
#define CLIONPROJECT_DZKRP_H
#include <stdio.h>
#include <stdlib.h>
#include "pairing_param.h"
#include "DPKRS.h"

typedef struct
{
    signed long x_v;
    element_t x;
    element_t r1;
    element_t r2;
    element_t m;
    element_t new_m;
} dz_msg_t;

typedef struct
{
    element_t *r1_list;
    element_t *r2_list;
} dz_ran_num_list_t;



typedef struct
{
    dp_sig_t *sig;
    dp_sign_info_t *sign_info;
} dz_bit_proof_t;

typedef struct
{
    dz_bit_proof_t *bit_proofs;
    int n;
    element_t M;
} dz_proof_t;

typedef struct
{
    dz_proof_t * tx_proof;
    dz_proof_t * balance_proof;
} dz_proofs_t;


class DZKRP{
public:
    static dz_msg_t *get_msg(pub_param_t *pp, signed long value)
    {

        dz_msg_t *msg = (dz_msg_t *)malloc(sizeof(dz_msg_t));
        msg->x_v = value;

        get_Zr_element(pp, msg->x);
        get_Zr_element(pp, msg->r1);
        get_Zr_element(pp, msg->r2);

        get_Gt_element(pp, msg->new_m);
        get_Gt_element(pp, msg->m);

        set_Zr_element_value(pp, msg->x, value);
        element_random(msg->r1);
        element_random(msg->r2);

        cal_msg(pp, msg);
        return msg;
    }

    static void cal_msg(pub_param_t *pp, dz_msg_t *msg)
    {
        element_t g1_x, h1_r1, h2_r2, temp;

        get_Gt_element(pp, g1_x);
        get_Gt_element(pp, h1_r1);
        get_Gt_element(pp, h2_r2);

        element_pp_pow_zn(g1_x, msg->x, pp->Gt_g1_pp);
        element_pp_pow_zn(h1_r1, msg->r1, pp->Gt_h1_pp);
        element_pp_pow_zn(h2_r2, msg->r2, pp->Gt_h2_pp);

        element_add(msg->new_m, g1_x, h1_r1);
        element_add(msg->m, msg->new_m, h2_r2);
    }

    static void prove(pub_param_t *pp, dz_msg_t *balance_info, dz_msg_t *tx_info, int l, char *m, dz_proofs_t* proofs)
    {
        // prove x >= 0
        dz_proof_t * tx_proof = prove_value(pp, tx_info->x_v, tx_info->r1, tx_info->r2, l, m);

        element_t new_x, new_r1, new_r2;
        get_Zr_element(pp, new_x);
        get_Zr_element(pp, new_r1);
        get_Zr_element(pp, new_r2);

        dz_msg_t *new_balance = (dz_msg_t *)malloc(sizeof(dz_msg_t));

        new_balance->x_v = balance_info->x_v - tx_info->x_v;

        get_Zr_element(pp, new_balance->x);
        get_Zr_element(pp, new_balance->r1);
        get_Zr_element(pp, new_balance->r2);

        get_Gt_element(pp, new_balance->new_m);
        get_Gt_element(pp, new_balance->m);


        element_sub(new_balance->x, balance_info->x, tx_info->x);
        element_sub(new_balance->r1, balance_info->r1, tx_info->r1);
        element_sub(new_balance->r2, balance_info->r2, tx_info->r2);

        cal_msg(pp, new_balance);

        // prove new_balance >= 0
        dz_proof_t* new_balance_proof = prove_value(pp, new_balance->x_v, new_balance->r1, new_balance->r2, l, m);

        proofs->balance_proof = new_balance_proof;
        proofs->tx_proof = tx_proof;
    }


    static int verify(pub_param_t *pp, dz_proofs_t *proofs,  element_t bal_value, element_t tx_value, char* m){
        dz_proof_t* bal_proof = proofs->balance_proof;
        dz_proof_t* tx_proof = proofs->tx_proof;
        int tx_result = verify_value(pp, m, tx_proof, tx_value);
        if (tx_result !=1)
        {
            return 0;
        }


        element_t new_bal;
        get_Gt_element(pp, new_bal);
        element_sub(new_bal, bal_value, tx_value);
        int new_bal_result = verify_value(pp, m, bal_proof, new_bal);
        if (new_bal_result !=1)
        {
            return 0;
        }


        return 1;
    }

    static void dz_get_M(pub_param_t *pp, element_t x, element_t r1, element_t r2, element_t M)
    {
        element_t g1_x;
        element_t h1_r1;
        element_t h2_r2;
        element_t temp1;
        element_t temp2;

        get_Gt_element(pp, g1_x);
        get_Gt_element(pp, h1_r1);
        get_Gt_element(pp, h2_r2);
        get_Gt_element(pp, temp1);
        get_Gt_element(pp, temp2);

        element_pp_pow_zn(g1_x, x, pp->Gt_g1_pp);

        element_pp_pow_zn(h1_r1, r1, pp->Gt_h1_pp);
        element_pp_pow_zn(h2_r2, r2, pp->Gt_h2_pp);

        element_add(temp1, g1_x, h1_r1);
        element_add(M, temp1, h2_r2);
    }

    static dz_proof_t *prove_value(pub_param_t *pp, signed long x, element_t r1, element_t r2, int l, char *m)
    {
        dz_proof_t *proof = (dz_proof_t *)malloc(sizeof(dz_proof_t));
        proof->n = l;
        proof->bit_proofs = (dz_bit_proof_t *)malloc(sizeof(dz_bit_proof_t) * l);
        get_Gt_element(pp, proof->M);

        dz_ran_num_list_t *num_list = get_ran_nums(pp, r1, r2, l);

        element_t *x_bins = get_value_bin(pp, x, l);

        element_t x_;
        set_Zr_element_value(pp, x_, x);
        dz_get_M(pp, x_, r1, r2, proof->M);

        element_t one_Zr, two_Zr;
        get_Zr_element(pp, one_Zr);
        get_Zr_element(pp, two_Zr);

        element_set1(one_Zr);
        element_double(two_Zr, one_Zr);

        element_t two_mul;
        get_Zr_element(pp, two_mul);
        element_set1(two_mul);

        for (int i = 0; i < l; i++)
        {
            int idx = l - 1 - i;

            if (i > 0)
            {
                element_mul_zn(two_mul, two_mul, two_Zr);
            }

            element_t value;
            get_Zr_element(pp, value);
            element_mul_zn(value, x_bins[idx], two_mul);
            // element_printf("%B\n", value);

            element_t h1_r1, h2_r2, g1_value;

            get_Gt_element(pp, h1_r1);
            get_Gt_element(pp, h2_r2);
            get_Gt_element(pp, g1_value);

            element_pp_pow_zn(h1_r1, num_list->r1_list[i], pp->Gt_h1_pp);
            element_pp_pow_zn(h2_r2, num_list->r2_list[i], pp->Gt_h2_pp);
            element_pp_pow_zn(g1_value, value, pp->Gt_g1_pp);

            element_t temp, pk_0, pk_1, g1_two_mul;
            get_Gt_element(pp, temp);
            get_Gt_element(pp, pk_0);
            get_Gt_element(pp, pk_1);
            get_Gt_element(pp, g1_two_mul);

            element_add(temp, h1_r1, h2_r2);

            // pk_0 = g1^value h1^r1 h2^r2
            element_add(pk_0, g1_value, temp);

            element_pp_pow_zn(g1_two_mul, two_mul, pp->Gt_g1_pp);
            // pk_1 = g1^value h1^r1 h2^r2 / g1^{2^bin}
            element_sub(pk_1, pk_0, g1_two_mul);
            if (!(element_cmp(x_bins[idx], one_Zr)))
            {
                element_t ss_value;
                get_Gt_element(pp, ss_value);
                element_set(ss_value, pk_0);
                element_set(pk_0, pk_1);
                element_set(pk_1, ss_value);
            }

            element_t *pk_list = (element_t *)malloc(sizeof(element_t) * 2);
            get_Gt_element(pp, pk_list[0]);
            get_Gt_element(pp, pk_list[1]);

            element_set(pk_list[0], pk_0);
            element_set(pk_list[1], pk_1);

            // proof->bit_proofs[i] = (dz_bit_proof_t *)malloc(sizeof(dz_bit_proof_t));

            // dz_bit_proof_t *bit_proof = (dz_bit_proof_t *)malloc(sizeof(dz_bit_proof_t));

            proof->bit_proofs[i].sign_info =  DPKRS::dp_get_sign_info(pp, 2, pk_list);

            // bit_proof->sign_info = dp_get_sign_info(pp, 2, pk_list);

            proof->bit_proofs[i].sig = DPKRS::dp_sign(pp, m, proof->bit_proofs[i].sign_info, num_list->r1_list[i], num_list->r2_list[i]);

            // int dp_result = dp_verify(pp, proof->bit_proofs[i].sig, m, proof->bit_proofs[i].sign_info);
            // if (dp_result != 1)
            // {
            //     printf("verify error!");
            // }


        }

        return proof;
    }

    static int verify_value(pub_param_t *pp, char *m, dz_proof_t *proof, element_t M)
    {
        // check if M = \Pi bitproof
        element_t M_;
        get_Gt_element(pp, M_);
        element_set0(M_);
        dz_bit_proof_t *bit_proofs = proof->bit_proofs;

        for (int i = 0; i < proof->n; i++)
        {
            int result = DPKRS::dp_verify(pp, bit_proofs[i].sig, m, bit_proofs[i].sign_info);
            if (result != 1)
            {
//                printf("bit value verify error in dzkrp\n");
                return 0;
            }
            element_add(M_, M_, bit_proofs[i].sign_info->pk_list[0]);
        }
        if (!element_cmp(M_, M))
        {
//            printf("recoverd message verify error in dzkrp\n");
            return 0;
        }

        return 1;
    }

    static element_t *get_value_bin(pub_param_t *pp, signed long x, int l)
    {

        element_t *result = (element_t *)malloc(sizeof(element_t) * l);

        signed long mask = 1L << (l - 1);

        for (int i = 0; i < l; i++)
        {
            signed long bit_value = (x & mask) ? 1 : 0;
            set_Zr_element_value(pp, result[i], bit_value);
            mask >>= 1;
        }

        return result;
    }

    static dz_ran_num_list_t *get_ran_nums(pub_param_t *pp, element_t r1, element_t r2, int l)
    {
        element_t *r1_list = (element_t *)malloc(sizeof(element_t) * l);
        element_t *r2_list = (element_t *)malloc(sizeof(element_t) * l);
        element_t r1_sum, r2_sum;
        get_Zr_element(pp, r1_sum);
        get_Zr_element(pp, r2_sum);

        element_set0(r1_sum);
        element_set0(r2_sum);

        for (int i = 1; i < l; i++)
        {
            get_Zr_element(pp, r1_list[i]);
            get_Zr_element(pp, r2_list[i]);
            element_random(r1_list[i]);
            element_random(r2_list[i]);
            element_add(r1_sum, r1_sum, r1_list[i]);
            element_add(r2_sum, r2_sum, r2_list[i]);
        }

        get_Zr_element(pp, r1_list[0]);
        get_Zr_element(pp, r2_list[0]);
        element_sub(r1_list[0], r1, r1_sum);
        element_sub(r2_list[0], r2, r2_sum);

        dz_ran_num_list_t *num_list = (dz_ran_num_list_t *)malloc(sizeof(dz_ran_num_list_t));
        num_list->r1_list = r1_list;
        num_list->r2_list = r2_list;
        return num_list;
    }
};



#endif //CLIONPROJECT_DZKRP_H
