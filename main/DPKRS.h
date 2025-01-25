//
// Created by archer-oneee on 11/26/24.
//

#ifndef CLIONPROJECT_DPKRS_H
#define CLIONPROJECT_DPKRS_H
#include <stdio.h>
#include <time.h>
#include <cstring>
#include "pairing_param.h"

typedef struct
{
    element_t sk;
    element_t skp;
    element_t Gt_pk;
} dp_keypair_t;

typedef struct
{
    element_t *pk_list;
    char *pk_list_str;
    int n;
} dp_sign_info_t;

typedef struct
{
    element_t v_0;
    element_t *beta_list;
    element_t *betap_list;
} dp_sig_t;

void dp_set_up(pub_param_t *pp)
{
    read_file(pp);
}
class DPKRS{
public:
    static void dp_key_gen(pub_param_t *pp, dp_keypair_t *key_pair)
    {

        element_t w;
        get_Zr_element(pp, w);
        element_random(w);

        element_t temp1, temp2;
        element_init_Zr(key_pair->sk, pp->pairing);
        element_init_Zr(key_pair->skp, pp->pairing);
        element_init_GT(key_pair->Gt_pk, pp->pairing);
        get_Gt_element(pp, temp1);
        get_Gt_element(pp, temp2);

        element_random(key_pair->sk);
        element_random(key_pair->skp);

        element_pp_pow_zn(temp1, key_pair->sk, pp->Gt_h1_pp);
        element_pp_pow_zn(temp2, key_pair->skp, pp->Gt_h2_pp);
        element_add(key_pair->Gt_pk, temp1, temp2);

        printf("key gen down!\n");
    }

    static dp_sign_info_t *dp_get_sign_info(pub_param_t *pp, int n, element_t *pk_list){
        dp_sign_info_t *sign_info = (dp_sign_info_t *)malloc(sizeof(sign_info));
        sign_info->n = n;

        sign_info->pk_list = pk_list;
        sign_info->pk_list_str = dp_get_pkL_str(pk_list, n);
        return sign_info;
    }

    static dp_sign_info_t *dp_create_keys(pub_param_t *pp, int n, element_t pk_0)
    {

        dp_sign_info_t *sign_info = (dp_sign_info_t *)malloc(sizeof(sign_info));
        sign_info->n = n;

        element_t *pk_list;
        pk_list = (element_t *)malloc(sizeof(element_t) * n);

        for (int i = 0; i < n; i++)
        {
            get_Gt_element(pp, pk_list[i]);
            if (i == 0)
            {
                element_set(pk_list[i], pk_0);
            }
            else
            {
                element_random(pk_list[i]);
            }
        }
        sign_info->pk_list = pk_list;

        sign_info->pk_list_str = dp_get_pkL_str(pk_list, n);
        return sign_info;
    }

    static char *dp_get_pkL_str(element_t *pk_list, int n)
    {
        size_t total_length = 1; // 初始字符串长度为1，用于存储空字符'\0'

        for (int i = 0; i < n; i++)
        {
            char *tempStr = element_2_str(pk_list[i]);
            total_length += strlen(tempStr);
            free(tempStr);
        }

        char *result = (char *)malloc(total_length);
        result[0] = '\0'; // 初始化为空字符串

        for (int i = 0; i < n; i++)
        {
            char *tempStr = element_2_str(pk_list[i]);
            strcat(result, tempStr); // 将字符串拼接到结果中
            free(tempStr);
        }

        return result;
    }


    static dp_sig_t *dp_sign(pub_param_t *pp, char *m, dp_sign_info_t *sign_info, element_t sk, element_t skp)
    {
        element_t *pk_list = sign_info->pk_list;
        char *pk_list_str = sign_info->pk_list_str;
        int n = sign_info->n;

        element_t alpha_0, alphap_0;
        get_Zr_element(pp, alpha_0);
        get_Zr_element(pp, alphap_0);

        element_random(alpha_0);

        element_random(alphap_0);

        element_t temp0, temp1, u_0;
        get_Gt_element(pp, temp0);
        get_Gt_element(pp, temp1);
        get_Gt_element(pp, u_0);

        element_pp_pow_zn(temp0, alpha_0, pp->Gt_h1_pp);
        element_pp_pow_zn(temp1, alphap_0, pp->Gt_h2_pp);
        element_add(u_0, temp0, temp1);
        char *m_l_u = dp_get_mlu(m, u_0, pk_list_str);

        element_t v_0;
        get_Zr_element(pp, v_0);
        element_from_hash(v_0, m_l_u, strlen(m_l_u));

        element_t *u_list = (element_t *)malloc(sizeof(element_t) * n);
        element_t *v_list = (element_t *)malloc(sizeof(element_t) * n);
        element_t *beta_list = (element_t *)malloc(sizeof(element_t) * n);
        element_t *betap_list = (element_t *)malloc(sizeof(element_t) * n);

        for (int i = 0; i < n; i++)
        {
            get_Gt_element(pp, u_list[i]);
            get_Zr_element(pp, v_list[i]);
            get_Zr_element(pp, beta_list[i]);
            get_Zr_element(pp, betap_list[i]);
        }

        element_set(u_list[0], u_0);
        element_set(v_list[0], v_0);

        for (int i = 1; i < n; i++)
        {
            element_t beta_i, betap_i;
            Zr_random(pp, beta_i);
            Zr_random(pp, betap_i);

            element_set(beta_list[i], beta_i);
            element_set(betap_list[i], betap_i);

            element_t h1_beta_i, h2_betap_i, pk_v_i;
            get_Gt_element(pp, h1_beta_i);
            get_Gt_element(pp, h2_betap_i);
            get_Gt_element(pp, pk_v_i);

            element_pp_pow_zn(h1_beta_i, beta_i, pp->Gt_h1_pp);
            element_pp_pow_zn(h2_betap_i, betap_i, pp->Gt_h2_pp);
            element_pow_zn(pk_v_i, pk_list[i], v_list[i - 1]);

            element_t temp2;
            get_Gt_element(pp, temp2);

            element_add(temp2, h1_beta_i, h2_betap_i);
            element_add(u_list[i], temp2, pk_v_i);
            m_l_u = dp_get_mlu(m, u_list[i], pk_list_str);
            element_from_hash(v_list[i], m_l_u, strlen(m_l_u));
        }

        int last = n - 1;
        element_t sk_vlast;
        element_t skp_vlast;
        get_Zr_element(pp, sk_vlast);
        get_Zr_element(pp, skp_vlast);
        element_mul_zn(sk_vlast, sk, v_list[last]);
        element_mul_zn(skp_vlast, skp, v_list[last]);

        element_t beta_0, betap_0;
        get_Zr_element(pp, beta_0);
        get_Zr_element(pp, betap_0);

        element_sub(beta_0, alpha_0, sk_vlast);
        element_sub(betap_0, alphap_0, skp_vlast);
        element_set(beta_list[0], beta_0);
        element_set(betap_list[0], betap_0);

        dp_sig_t *sig = (dp_sig_t *)malloc(sizeof(dp_sig_t));

        get_Zr_element(pp, sig->v_0);
        element_set(sig->v_0, v_0);
        sig->beta_list = beta_list;
        sig->betap_list = betap_list;
//        printf("dp sign done!\n");
        return sig;
    }

    static int dp_verify(pub_param_t *pp, dp_sig_t *sig, char *m, dp_sign_info_t *sign_info)
    {
        element_t *pk_list = sign_info->pk_list;
        char *pk_list_str = sign_info->pk_list_str;
        int n = sign_info->n;

        element_t v_0;
        get_Zr_element(pp, v_0);
        element_set(v_0, sig->v_0);

        element_t *beta_list = sig->beta_list;
        element_t *betap_list = sig->betap_list;
        element_t *v_list = (element_t *)malloc(sizeof(element_t) * n);
        for (int i = 0; i < n; i++)
        {
            element_init_same_as(v_list[i], v_0);
        }

        element_set(v_list[0], v_0);

        char *m_l_u;

        for (int i = 1; i < n; i++)
        {
            element_t h1_beta_i, h2_betap_i, pk_v_i;
            get_Gt_element(pp, h1_beta_i);
            get_Gt_element(pp, h2_betap_i);
            get_Gt_element(pp, pk_v_i);

            element_pp_pow_zn(h1_beta_i, beta_list[i], pp->Gt_h1_pp);
            element_pp_pow_zn(h2_betap_i, betap_list[i], pp->Gt_h2_pp);
            element_pow_zn(pk_v_i, pk_list[i], v_list[i - 1]);

            element_t temp2, u_i;
            get_Gt_element(pp, temp2);
            get_Gt_element(pp, u_i);

            element_add(temp2, h1_beta_i, h2_betap_i);
            element_add(u_i, temp2, pk_v_i);

            m_l_u = dp_get_mlu(m, u_i, pk_list_str);
            element_from_hash(v_list[i], m_l_u, strlen(m_l_u));
        }

        int last = n - 1;
        element_t h1_beta_0, h2_betap_0, pk_v_n, temp, u_0, v_0_;
        get_Gt_element(pp, h1_beta_0);
        get_Gt_element(pp, h2_betap_0);
        get_Gt_element(pp, pk_v_n);
        get_Gt_element(pp, temp);
        get_Gt_element(pp, u_0);
        get_Zr_element(pp, v_0_);

        element_pp_pow_zn(h1_beta_0, beta_list[0], pp->Gt_h1_pp);
        element_pp_pow_zn(h2_betap_0, betap_list[0], pp->Gt_h2_pp);
        element_add(temp, h1_beta_0, h2_betap_0);

        element_pow_zn(pk_v_n, pk_list[0], v_list[last]);

        element_add(u_0, temp, pk_v_n);

        m_l_u = dp_get_mlu(m, u_0, pk_list_str);

        element_from_hash(v_0_, m_l_u, strlen(m_l_u));

        if (!element_cmp(v_0_, v_0))
        {
//            printf("dp signature verify successfully!\n");
            return 1;
        }
        else
        {
//            printf("dp signature verify faild!\n");
            return 0;
        }
    }

    static char *dp_get_mlu(char *m, element_t u, char *pk_list_str)
    {

         char *u_str = element_2_str(u);
        size_t all_len = strlen(m) + strlen(u_str) + strlen(pk_list_str) + 1;
        char *concatenated_str = (char *)malloc(all_len);
        memset(concatenated_str, 0, all_len);

        strcat(concatenated_str, m);
        strcat(concatenated_str, u_str);
        strcat(concatenated_str, pk_list_str);

        return concatenated_str;
    }

};


#endif //CLIONPROJECT_DPKRS_H
