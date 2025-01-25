#include "PBC.h" //包含pbcwrapper的头文件PBC.h
#include "pairing_param.h"
#include "global.h"
#include "DBSign.h"
#include "DPKRS.h"
#include "DZKRP.h"
#include "user.h"
#include "tumbler.h"
#include "payment_channel.h"

void test1(){
    //初始化配对变量e
    char param[1024];
    const char *paramFileName =  "/home/archer-oneee/Desktop/ClionProject/pairing.param";

    FILE* file = fopen(paramFileName, "r");
    size_t count = fread(param, 1, 1024, file);
    fclose(file);
    if (!count) pbc_die("input error");
    Pairing e(param, count);

    G2 g(e);
    Zr secret_key(e);

    G2 public_key = g ^ secret_key; //指数运算
    G1 h(e, (void*)"ABCDEF", 6);
    G1 sig = h ^ secret_key;

    GT temp1 = e(sig, g); //配对运算
    GT temp2 = e(h, public_key);
    if (temp1 == temp2) {
        printf("signature verifies\n");
    } else {
        printf("signature does not verify\n");
    }
}

pub_param_t *setup(pub_param_t *pp)
{
    read_file(pp);
    return pp;
}

void test2(){
    pub_param_t * pp = (pub_param_t *)malloc(sizeof(pub_param_t));
    setup(pp);
    element_t zr_random;
    Zr_random(pp, zr_random);
    char * result = element_2_str(zr_random);
}

void DBSign_test(){
    pub_param_t * pp = (pub_param_t *)malloc(sizeof(pub_param_t));
    setup(pp);
    db_keypair_t *key_pair = (db_keypair_t *) malloc(sizeof(db_keypair_t));
    db_sig_t *sig = (db_sig_t *)malloc(sizeof(db_sig_t));
    db_sig_t *new_sig = (db_sig_t *)malloc(sizeof(db_sig_t));
    db_msg_t *msg = (db_msg_t *)malloc(sizeof(db_msg_t));

    DBSign::key_gen(pp, key_pair);

    Zr_random(pp, msg->x);
    Zr_random(pp, msg->r1);
    Zr_random(pp, msg->r2);
    get_G1_element(pp, msg->m);
    get_G1_element(pp, msg->new_m);


    DBSign::cal_M(pp, msg);

    DBSign::sign(pp, msg->m, key_pair->sk, sig);
    DBSign::verify(pp, sig, msg->m, key_pair->G2_pk);

    DBSign::ran_unblind(pp, sig, new_sig, msg);


    DBSign::verify(pp, new_sig, msg->new_m, key_pair->G2_pk);
}

void DPKRS_test(){
    // test();
    /* code */
    pub_param_t * pp = (pub_param_t *)malloc(sizeof(pub_param_t));
    setup(pp);

    int n = 3;


    dp_keypair_t *key_pair = (dp_keypair_t *)malloc(sizeof(dp_keypair_t));
    DPKRS::dp_key_gen(pp, key_pair);

    dp_sign_info_t *sign_info = DPKRS::dp_create_keys(pp, n, key_pair->Gt_pk);
    char m[] = "test";

    dp_sig_t *sig = DPKRS::dp_sign(pp, m, sign_info, key_pair->sk, key_pair->skp);
    DPKRS::dp_verify(pp, sig, m, sign_info);
}

void test_DZKRP(){
    // test();
    /* code */
    pub_param_t * pp = (pub_param_t *)malloc(sizeof(pub_param_t));
    setup(pp);

    int n = 3;
    int l = get_MAX_BIT_LENGTH();

    signed long value_ba = 3;
    signed long value_tx = 1;

    char *m = "test";
    element_t balance, tx;
    // set_Zr_element_value(pp, balance, valueBa);
    // element_printf("%B", balance);
    dz_msg_t *ba_msg = DZKRP::get_msg(pp, value_ba);
    dz_msg_t *tx_msg = DZKRP::get_msg(pp, value_tx);

    dz_proofs_t* proofs = (dz_proofs_t *) malloc(sizeof(dz_proofs_t));
    DZKRP::prove(pp, ba_msg, tx_msg, l, m, proofs);
    int result = DZKRP::verify(pp, proofs, ba_msg->m, tx_msg->m, m);

    // dz_proof_t *proof = prove_value(pp, ba_msg->x_v, ba_msg->r1, ba_msg->r2, l, m);


    // int result = verify_value(pp, m, proof, ba_msg->m);

    if (result==1)
    {
        printf("success-----------\n");
    }
}


int main() {


    pub_param_t * pp = (pub_param_t *)malloc(sizeof(pub_param_t));
    setup(pp);
    int round = 1000;


    int sender_value = 10000000;
    int receiver_value = 10000000;
    int tumbler_value = 10000000;
    int version = 0;
    User sender(pp, sender_value);
    User receiver(pp, receiver_value);
    Tumbler tumbler(pp, tumbler_value);

    for (int i = 0; i < 50; ++i) {
        //open phase
        PaymentChannel pc_st(&tumbler, &sender);
        PaymentChannel pc_rt(&tumbler, &receiver);
        pc_st.open_phase(version);
        pc_rt.open_phase(version);

        int tx_value = 1;
        //puzzle promise phase
        puzzle_t res = pc_rt.puzzle_promise1(tx_value);
        auto [puzzle, proofs] = pc_st.puzzle_promise2(res);

        //puzzle solve phase
        db_sig_t *sig = pc_st.puzzle_solve1(puzzle, proofs);
        pc_st.puzzle_solve2(puzzle, sig);

        db_sig_t *new_sig = pc_rt.puzzle_solve3(puzzle, sig);
        pc_rt.puzzle_solve4(puzzle, new_sig);
    }

    PaymentChannel pc_st(&tumbler, &sender);
    PaymentChannel pc_rt(&tumbler, &receiver);
    pc_st.open_phase(version);
    pc_rt.open_phase(version);
    auto start = chrono::high_resolution_clock ::now();
    chrono::duration<double, milli> all_payee = start - start;
    chrono::duration<double, milli> all_tumbler = start - start;

    for (int i = 0; i < round; ++i) {
        //open phase
        int tx_value = 1;
        //puzzle promise phase
        auto payee_start = chrono::high_resolution_clock ::now();
        puzzle_t res = pc_rt.puzzle_promise1(tx_value);
        auto payee_end = chrono::high_resolution_clock ::now();
        chrono::duration<double, milli> cost = payee_end - payee_start;
        all_payee += cost;

        auto [puzzle, proofs] = pc_st.puzzle_promise2(res);



        auto tumbler_start = chrono::high_resolution_clock ::now();
        //puzzle solve phase
        db_sig_t *sig = pc_st.puzzle_solve1(puzzle, proofs);
        auto tumbler_end = chrono::high_resolution_clock ::now();
        chrono::duration<double, milli> tumbler_cost = tumbler_end - tumbler_start;
        all_tumbler += tumbler_cost;

        pc_st.puzzle_solve2(puzzle, sig);

        db_sig_t *new_sig = pc_rt.puzzle_solve3(puzzle, sig);

        tumbler_start = chrono::high_resolution_clock ::now();
        pc_rt.puzzle_solve4(puzzle, new_sig);
        tumbler_end = chrono::high_resolution_clock ::now();
        tumbler_cost = tumbler_end - tumbler_start;
        all_tumbler += tumbler_cost;
    }
    auto end = chrono::high_resolution_clock ::now();
    chrono::duration<double, milli> cost = end - start;
    cout<< "cost time" << (cost.count())/round << "ms" << endl;
    cout<< "payee cost time" << (all_payee.count())/round << "ms" << endl;
    cout<< "all_tumbler cost time" << (all_tumbler.count())/round << "ms" << endl;


    int a = 1;
    return 0;

}