

//
// Created by archer-oneee on 11/26/24.
//

#ifndef CLIONPROJECT_PAIRING_PARAM_H
#define CLIONPROJECT_PAIRING_PARAM_H
#include "PBC.h"

typedef struct
{
    pairing_t pairing;
    pairing_pp_t pp; // e(x, G2_g)
    element_t G2_g;  // G2
    element_t G1_g1; // G1
    element_t G1_g2; // G1
    element_t G1_h1; // G1
    element_t G1_h2; // G1
    element_t Gt_g1;  // G1 e(G1_g1, G2_g);
    element_t Gt_h1; // G1 e(G1_h1, G2_g);
    element_t Gt_h2; // G1 e(G1_h2, G2_g);
    element_pp_t G1_g1_pp;
    element_pp_t G1_g2_pp;
    element_pp_t G1_h1_pp;
    element_pp_t G1_h2_pp;
    element_pp_t G2_g_pp;
    element_pp_t Gt_g1_pp;
    element_pp_t Gt_h1_pp;
    element_pp_t Gt_h2_pp;
} pub_param_t;

extern pub_param_t *pp;


void read_file(pub_param_t *pp);

void init_elements(pub_param_t *pp);

void get_G1_element(pub_param_t *pp, element_t temp);

void get_G2_element(pub_param_t *pp, element_t temp);

void get_Zr_element(pub_param_t *pp, element_t temp);

void get_Gt_element(pub_param_t *pp, element_t temp);

void get_G1_element(pub_param_t *pp, element_t temp)
{

    element_init_G1(temp, pp->pairing);
}

void read_file(pub_param_t *pp)
{
    FILE *file;
    long file_size;
    char file_name[] = "/home/archer-oneee/pbc/param/a.param";
    char param[1024];

    // 打开文件
    file = fopen(file_name, "rb");
    if (file == NULL)
    {
        printf("无法打开文件\n");
        return;
    }

    size_t count = fread(param, 1, 1024, file);

//    printf("%s\n", param);

    if (!count)
        pbc_die("input error");
    pairing_init_set_buf(pp->pairing, param, count);

    fclose(file);
    init_elements(pp);
}

void init_elements(pub_param_t *pp)
{

    element_init_G1(pp->G1_g1, pp->pairing);
    element_init_G1(pp->G1_g2, pp->pairing);
    element_init_G1(pp->G1_h1, pp->pairing);
    element_init_G1(pp->G1_h2, pp->pairing);
    element_init_G2(pp->G2_g, pp->pairing);
    element_init_GT(pp->Gt_g1, pp->pairing);
    element_init_GT(pp->Gt_h1, pp->pairing);
    element_init_GT(pp->Gt_h2, pp->pairing);

    // generate system parameters
    element_random(pp->G1_g1);
    element_random(pp->G1_g2);
    element_random(pp->G1_h1);
    element_random(pp->G1_h2);
    element_random(pp->G2_g);

    element_t temp;
    get_G1_element(pp, temp);
    element_add(temp, pp->G1_h1, pp->G1_h2);

    element_pairing(pp->Gt_g1, temp, pp->G2_g);

    element_pairing(pp->Gt_h1, pp->G1_h1, pp->G2_g);
    element_pairing(pp->Gt_h2, pp->G1_h2, pp->G2_g);

    pairing_pp_init(pp->pp, pp->G2_g, pp->pairing); // x is some element of G1
    element_pp_init(pp->G1_g1_pp, pp->G1_g1);
    element_pp_init(pp->G1_g2_pp, pp->G1_g2);
    element_pp_init(pp->G1_h1_pp, pp->G1_h1);
    element_pp_init(pp->G1_h2_pp, pp->G1_h2);
    element_pp_init(pp->G2_g_pp, pp->G2_g);

    element_pp_init(pp->Gt_g1_pp, pp->Gt_g1);
    element_pp_init(pp->Gt_h1_pp, pp->Gt_h1);
    element_pp_init(pp->Gt_h2_pp, pp->Gt_h2);
}





void get_G2_element(pub_param_t *pp, element_t temp)
{
    element_init_G2(temp, pp->pairing);
}

void get_Zr_element(pub_param_t *pp, element_t temp)
{
    element_init_Zr(temp, pp->pairing);
}

void set_Zr_element_value(pub_param_t *pp, element_t temp, signed long value)
{
    element_init_Zr(temp, pp->pairing);
    element_set_si(temp, value);
}

void get_Gt_element(pub_param_t *pp, element_t temp)
{
    element_init_GT(temp, pp->pairing);
}

void Zr_random(pub_param_t *pp, element_t temp)
{
    element_init_Zr(temp, pp->pairing);
    element_random(temp);
}

void pairing_apply_(pub_param_t *pp, element_t temp, element_t x)
{
    pairing_pp_apply(temp, x, pp->pp); // temp = e(G2_g, x)
}

char *element_2_str(element_t temp)
{
    size_t len = element_length_in_bytes(temp);
    unsigned char *buffer = (unsigned char *)malloc(len);
    element_to_bytes(buffer, temp);


    // // 将字节数组转换为十六进制字符串
    char *tempStr = (char *)malloc(len * 2 + 1);
    for (size_t j = 0; j < len; j++)
    {
        sprintf(tempStr + (j * 2), "%02X", buffer[j]);
    }
    tempStr[len * 2] = '\0';
    return tempStr;


    // return buffer;


}
#endif

