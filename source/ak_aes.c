#include <wmmintrin.h>
#include <ak_bckey.h>
#include <ak_tools.h>
#include "libakrypt.h"

/*! \brief Вспомогательная функция для алгоритма развертки ключа (согласно Intel® AES-NI). */
inline void aes_key_256_assist_1(__m128i* temp1, __m128i* temp2)
{
    __m128i temp4;
    *temp2 = _mm_shuffle_epi32(*temp2, 0xff);
    temp4 = _mm_slli_si128(*temp1, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4  = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    temp4  = _mm_slli_si128(temp4, 0x4);
    *temp1 = _mm_xor_si128(*temp1, temp4);
    *temp1 = _mm_xor_si128(*temp1, *temp2);
}

/*! \brief Вспомогательная функция для алгоритма развертки ключа (согласно Intel® AES-NI). */
inline void aes_key_256_assist_2(__m128i* temp1, __m128i* temp3)
{
    __m128i temp2, temp4;
    temp4 = _mm_aeskeygenassist_si128(*temp1, 0x0);
    temp2 = _mm_shuffle_epi32(temp4, 0xaa);
    temp4 = _mm_slli_si128(*temp3, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    temp4 = _mm_slli_si128(temp4, 0x4);
    *temp3 = _mm_xor_si128(*temp3, temp4);
    *temp3 = _mm_xor_si128(*temp3, temp2);

}

/*! \brief Раундовые ключи алгоритма AES и маска для 0-раунда */
struct aes_expanded_keys {
    ak_uint128 k[15];
    ak_uint128 m;
};

/*! \brief Структура с внутренними данными секретного ключа алгоритма AES. */
struct aes_ctx {
    /*! \brief раундовые ключи и маска для алгоритма зашифрования */
    struct aes_expanded_keys encryptkey;
    /*! \brief раундовые ключи и маска для алгоритма расшифрования */
    struct aes_expanded_keys decryptkey;
};
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция освобождает память, занимаемую развернутыми ключами алгоритма AES. */
/* ----------------------------------------------------------------------------------------------- */
static int ak_aes_delete_keys( ak_skey skey )
{
    int error = ak_error_ok;

    /* выполняем стандартные проверки */
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer,
                                                __func__ , "using a null pointer to secret key" );
    if( skey->data == NULL ) return ak_error_message( ak_error_null_pointer,
                                                      __func__ , "using a null pointer to internal data" );
    /* теперь очистка и освобождение памяти */
    if(( error = skey->generator.random( &skey->generator,
                                         skey->data, sizeof( struct aes_ctx ))) != ak_error_ok ) {
        ak_error_message( error, __func__, "incorrect wiping an internal data" );
        memset( skey->data, 0, sizeof ( struct aes_ctx ));
    }
    if( skey->data != NULL ) {
        free( skey->data );
        skey->data = NULL;
    }

    return ak_error_ok;
}
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует развертку ключей для алгоритма AES (согласно Intel® AES-NI). */
/* ----------------------------------------------------------------------------------------------- */

static int ak_aes_schedule_keys( ak_skey skey)
{
    struct aes_expanded_keys *ekey = NULL, *dkey = NULL;
    int i;
    __m128i dkeys[15], keys[15];
    __m128i temp1, temp2, temp3;

    /* выполняем стандартные проверки */
    if( skey == NULL ) return ak_error_message( ak_error_null_pointer, __func__ ,
                                                "using a null pointer to secret key" );
    /* проверяем целостность ключа */
    if( skey->check_icode( skey ) != ak_true ) return ak_error_message( ak_error_wrong_key_icode,
                                                                        __func__ , "using key with wrong integrity code" );
    /* готовим память для переменных */
    if(( skey->data = /* далее, по-возможности, выделяем выравненную память */
#ifdef LIBAKRYPT_HAVE_STDALIGN
                 aligned_alloc( 16,
#else
                 malloc(
#endif
                         sizeof( struct aes_ctx ))) == NULL )
        return ak_error_message( ak_error_out_of_memory, __func__ ,
                                 "wrong allocation of internal data" );
    /* получаем указатели на области памяти */
    ekey = &(( struct aes_ctx * ) skey->data )->encryptkey;
    dkey = &(( struct aes_ctx * ) skey->data )->decryptkey;

    /* вырабатываем маски */
    skey->generator.random( &skey->generator,&(( struct aes_ctx * ) skey->data )->encryptkey.m, sizeof (ak_uint128));
    skey->generator.random( &skey->generator,&(( struct aes_ctx * ) skey->data )->decryptkey.m, sizeof (ak_uint128));

    /* только теперь выполняем алгоритм развертки ключа */
    temp1 = ((__m128i *)skey->key.data)[0];
    temp3 = ((__m128i *)skey->key.data)[1];

    temp1 = _mm_xor_si128(temp1, _mm_set_epi64x(( ( ak_uint128 *) skey->mask.data)[0].q[1], (( ak_uint128 *) skey->mask.data)[0].q[0]));
    temp3 = _mm_xor_si128(temp3, _mm_set_epi64x(( ( ak_uint128 *) skey->mask.data)[1].q[1], ( ( ak_uint128 *) skey->mask.data)[1].q[0]));

    keys[0] = temp1; dkeys[14] = keys[0];
    keys[1] = temp3; dkeys[13] = _mm_aesimc_si128(keys[1]);
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x01);
    aes_key_256_assist_1(&temp1, &temp2);
    keys[2] = temp1; dkeys[12] = _mm_aesimc_si128(keys[2]);
    aes_key_256_assist_2(&temp1, &temp3);
    keys[3] = temp3; dkeys[11] = _mm_aesimc_si128(keys[3]);
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x02);
    aes_key_256_assist_1(&temp1, &temp2);
    keys[4] = temp1; dkeys[10] = _mm_aesimc_si128(keys[4]);
    aes_key_256_assist_2(&temp1, &temp3);
    keys[5] = temp3; dkeys[9] = _mm_aesimc_si128(keys[5]);
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x04);
    aes_key_256_assist_1(&temp1, &temp2);
    keys[6] = temp1; dkeys[8] = _mm_aesimc_si128(keys[6]);
    aes_key_256_assist_2(&temp1, &temp3);
    keys[7] = temp3; dkeys[7] = _mm_aesimc_si128(keys[7]);
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x08);
    aes_key_256_assist_1(&temp1, &temp2);
    keys[8] = temp1; dkeys[6] = _mm_aesimc_si128(keys[8]);
    aes_key_256_assist_2(&temp1, &temp3);
    keys[9] = temp3; dkeys[5] = _mm_aesimc_si128(keys[9]);
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x10);
    aes_key_256_assist_1(&temp1, &temp2);
    keys[10] = temp1; dkeys[4] = _mm_aesimc_si128(keys[10]);
    aes_key_256_assist_2(&temp1, &temp3);
    keys[11] = temp3; dkeys[3] = _mm_aesimc_si128(keys[11]);
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x20);
    aes_key_256_assist_1(&temp1, &temp2);
    keys[12] = temp1; dkeys[2] = _mm_aesimc_si128(keys[12]);
    aes_key_256_assist_2(&temp1, &temp3);
    keys[13] = temp3; dkeys[1] = _mm_aesimc_si128(keys[13]);
    temp2 = _mm_aeskeygenassist_si128(temp3, 0x40);
    aes_key_256_assist_1(&temp1, &temp2);
    keys[14] = temp1; dkeys[0] = keys[14];

    for (i = 0; i<15; i++)
    {
        ekey->k[i].q[0] = ((ak_uint128 *)&keys[i])->q[0];
        ekey->k[i].q[1] = ((ak_uint128 *)&keys[i])->q[1];
        dkey->k[i].q[0] = ((ak_uint128 *)&dkeys[i])->q[0];
        dkey->k[i].q[1] = ((ak_uint128 *)&dkeys[i])->q[1];
    }

    ekey->k[0].q[0]^=ekey->m.q[0]; ekey->k[0].q[1]^=ekey->m.q[1];
    dkey->k[0].q[0]^=dkey->m.q[0]; dkey->k[0].q[1]^=dkey->m.q[1];

    memset(keys,0, 15* sizeof(__m128i));
    memset(dkeys,0, 15* sizeof(__m128i));
    return ak_error_ok;
}

/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм зашифрования одного блока информации
    шифром AES (согласно Intel® AES-NI).                                                           */
/* ----------------------------------------------------------------------------------------------- */
static void ak_aes_encrypt( ak_skey skey, ak_pointer in, ak_pointer out)
{
    int i ;
    __m128i text;
    struct aes_expanded_keys *ekey = &(( struct aes_ctx * ) skey->data )->encryptkey;

    text = *((__m128i *) in);
    text = _mm_xor_si128(text,_mm_set_epi64x(ekey->k[0].q[1], ekey->k[0].q[0]));
    text = _mm_xor_si128(text,_mm_set_epi64x(ekey->m.q[1], ekey->m.q[0]));

    for( i = 1; i < 14; i++ ) text = _mm_aesenc_si128(text, _mm_set_epi64x(ekey->k[i].q[1], ekey->k[i].q[0]));
    text = _mm_aesenclast_si128(text, _mm_set_epi64x(ekey->k[14].q[1], ekey->k[14].q[0]));

    *((__m128i *) out) = text;

}
/* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция реализует алгоритм расшифрования одного блока информации
    шифром AES (согласно Intel® AES-NI).                                                           */
/* ----------------------------------------------------------------------------------------------- */
static void ak_aes_decrypt( ak_skey skey, ak_pointer in, ak_pointer out)
{
    int i;
    __m128i t;
    struct aes_expanded_keys *dkey = &((struct aes_ctx *) skey->data)->decryptkey;

    t = *((__m128i *) in);
    t = _mm_xor_si128(t, _mm_set_epi64x(dkey->k[0].q[1], dkey->k[0].q[0]));
    t = _mm_xor_si128(t, _mm_set_epi64x(dkey->m.q[1], dkey->m.q[0]));

    for (i = 1; i < 14; i++) t = _mm_aesdec_si128(t, _mm_set_epi64x(dkey->k[i].q[1], dkey->k[i].q[0]));
    t = _mm_aesdeclast_si128(t, _mm_set_epi64x(dkey->k[14].q[1], dkey->k[14].q[0]));

    *((__m128i *) out) = t;

}

 /* ----------------------------------------------------------------------------------------------- */
/*! \brief Функция изменяет маску ключа алгоритма блочного шифрования AES.                    */
/* ----------------------------------------------------------------------------------------------- */
static int ak_aes_remask_xor( ak_skey skey )
{
    size_t idx = 0;
    ak_uint64 mask[4], m[2], *kptr = NULL, *mptr = NULL;
    int error = ak_error_ok;

    /* выполняем стандартные проверки */
    if (skey == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                                  "using a null pointer to secret key");
    if (skey->key.data == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                                  "using undefined key buffer");
    if (skey->key.size != 32)
        return ak_error_message(ak_error_wrong_length, __func__,
                                  "key length is wrong");
    if (skey->mask.data == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                                  "using undefined mask buffer");
    /* перемаскируем ключ */
    if ((error = skey->generator.random(&skey->generator, mask, skey->key.size)) != ak_error_ok)
        return ak_error_message(error, __func__, "wrong generation random key mask");

    for (idx = 0; idx < 4; idx++) {
        ((ak_uint64 *) skey->key.data)[idx] ^= mask[idx];
        ((ak_uint64 *) skey->key.data)[idx] ^= ((ak_uint64 *) skey->mask.data)[idx];
        ((ak_uint64 *) skey->mask.data)[idx] = mask[idx];
    }
    /* перемаскируем раундовый ключ зашифрования */
    if(( error = skey->generator.random( &skey->generator, m, 2*sizeof( ak_uint64 ))) != ak_error_ok )
        return ak_error_message( error, __func__, "wrong generation random key mask");

    kptr = (ak_uint64 *) ( &(( struct aes_ctx *)skey->data)->encryptkey );
    mptr = (ak_uint64 *) ( &(( struct aes_ctx *)skey->data)->encryptkey.m );
    for( idx = 0; idx < 2; idx++ ) {
        kptr[idx] ^= mask[idx];
        kptr[idx] ^= mptr[idx];
        mptr[idx] = mask[idx];
    }

    /* перемаскируем раундовый ключ расшифрования */
    if(( error = skey->generator.random( &skey->generator, m, 2*sizeof( ak_uint64 ))) != ak_error_ok )
        return ak_error_message( error, __func__, "wrong generation random key mask");

    kptr = (ak_uint64 *) ( &(( struct aes_ctx *)skey->data)->decryptkey);
    mptr = (ak_uint64 *) ( &(( struct aes_ctx *)skey->data)->decryptkey.m);
    for( idx = 0; idx < 2; idx++ ) {
        kptr[idx] ^= mask[idx];
        kptr[idx] ^= mptr[idx];
        mptr[idx] = mask[idx];
    }
      /* удаляем старое */
    memset( mask, 0, 4*sizeof( ak_uint64 ));
    memset( m, 0, 2*sizeof( ak_uint64 ));
    return ak_error_ok;
}
/* ----------------------------------------------------------------------------------------------- */
/*! Функция инициализирует контекст ключа алгоритма блочного шифрования AES.
    После инициализации устанавливаются обработчики (функции класса). Однако само значение
    ключу не присваивается - поле `bkey->key` остается неопределенным.

    @param bkey Контекст секретного ключа алгоритма блочного шифрования.

    @return Функция возвращает код ошибки. В случаее успеха возвращается \ref ak_error_ok.         */
/* ----------------------------------------------------------------------------------------------- */
int ak_bckey_create_aes(ak_bckey bkey)
{
    int error = ak_error_ok;
    if (bkey == NULL)
        return ak_error_message(ak_error_null_pointer, __func__,
                                    "using null pointer to block cipher key context");

    /* создаем ключ алгоритма шифрования и определяем его методы */
    if ((error = ak_bckey_create(bkey, 32, 16)) != ak_error_ok)
        return ak_error_message(error, __func__, "wrong initalization of block cipher key context");

    /* устанавливаем OID алгоритма шифрования */  //добавить в файле ak_oid.c
    if ((bkey->key.oid = ak_oid_find_by_name("aes")) == NULL) {
        error = ak_error_get_value();
        ak_error_message(error, __func__, "wrong search of predefined aes block cipher OID");
        ak_bckey_destroy(bkey);
        return error;
    };

    /* устанавливаем ресурс использования серетного ключа */
    bkey->key.resource.counter = ak_libakrypt_get_option("kuznechik_cipher_resource");

    /* устанавливаем методы */
    bkey->key.data = NULL;
    bkey->key.set_mask = ak_skey_set_mask_xor;
    bkey->key.remask = ak_aes_remask_xor;
    bkey->key.set_icode = ak_skey_set_icode_xor;
    bkey->key.check_icode = ak_skey_check_icode_xor;

    bkey->schedule_keys = ak_aes_schedule_keys;
    bkey->delete_keys = ak_aes_delete_keys;
    bkey->encrypt = ak_aes_encrypt;
    bkey->decrypt = ak_aes_decrypt;

    return error;
}

ak_bool ak_bckey_test_aes(void)
{
    char *str = NULL;
    struct bckey bkey;
    int error = ak_error_ok, audit = ak_log_get_level();

    /* тестовый ключ из NIST Special Publication 800-38A */
    ak_uint8 testkey[32] = {
                        0x60, 0x3d, 0xeb, 0x10, 0x15, 0xca, 0x71, 0xbe,
                        0x2b, 0x73, 0xae, 0xf0, 0x85, 0x7d, 0x77, 0x81,
                        0x1f, 0x35, 0x2c, 0x07, 0x3b, 0x61, 0x08, 0xd7,
                        0x2d, 0x98, 0x10, 0xa3, 0x09, 0x14, 0xdf, 0xf4 };

    /* открытый текст из NIST Special Publication 800-38A  */
    ak_uint8 in[16] = {
                 0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };

    /* зашифрованный блок из NIST Special Publication 800-38A */
    ak_uint8 out[16] = {
                 0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
                 0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7 };

    /* открытый текст из NIST Special Publication 800-38A*/
    ak_uint8 inlong[64] = {
                0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96,
                0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
                0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c,
                0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
                0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11,
                0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
                0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17,
                0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 };

    /* результат зашифрования в режиме простой замены из NIST Special Publication 800-38A */
    ak_uint8 outecb[64] = {
                0xf3, 0xee, 0xd1, 0xbd, 0xb5, 0xd2, 0xa0, 0x3c,
                0x06, 0x4b, 0x5a, 0x7e, 0x3d, 0xb1, 0x81, 0xf8,
                0x59, 0x1c, 0xcb, 0x10, 0xd4, 0x10, 0xed, 0x26,
                0xdc, 0x5b, 0xa7, 0x4a, 0x31, 0x36, 0x28, 0x70,
                0xb6, 0xed, 0x21, 0xb9, 0x9c, 0xa6, 0xf4, 0xf9,
                0xf1, 0x53, 0xe7, 0xb1, 0xbe, 0xaf, 0xed, 0x1d,
                0x23, 0x30, 0x4b, 0x7a, 0x39, 0xf9, 0xf3, 0xff,
                0x06, 0x7d, 0x8d, 0x8f, 0x9e, 0x24, 0xec, 0xc7 };


    ak_uint8 myout[64];

    /* 1. Создаем контекст ключа алгоритма AES и устанавливаем значение ключа */
    if ((error = ak_bckey_create_aes(&bkey)) != ak_error_ok) {
        ak_error_message(error, __func__, "incorrect initialization of aes secret key context");
        return ak_false;
    }

    if ((error = ak_bckey_context_set_ptr(&bkey, testkey, sizeof(testkey), ak_false)) != ak_error_ok) {
        ak_error_message(ak_error_get_value(), __func__, "wrong creation of test key");
        return ak_false;
    }

    /* 2. Тестируем зашифрование/расшифрование одного блока согласно NIST Special Publication 800-38A */
    bkey.encrypt(&bkey.key, in, myout);
    if (!ak_ptr_is_equal(myout, out, 16)) {
        ak_error_message_fmt(ak_error_not_equal_data, __func__,
                             "the one block encryption test from NIST SP 800-38A is wrong");
        ak_log_set_message(str = ak_ptr_to_hexstr(myout, 16, ak_true));
        free(str);
        ak_log_set_message(str = ak_ptr_to_hexstr(out, 16, ak_true));
        free(str);
        ak_bckey_destroy(&bkey);
        return ak_false;
    }
    if (audit >= ak_log_maximum)
        ak_error_message(ak_error_ok, __func__,
                         "the one block encryption test from NIST SP 800-38A is Ok");

    bkey.decrypt(&bkey.key, out, myout);
    if (!ak_ptr_is_equal(myout, in, 16)) {
        ak_error_message_fmt(ak_error_not_equal_data, __func__,
                             "the one block decryption test from NIST SP 800-38A is wrong");
        ak_log_set_message(str = ak_ptr_to_hexstr(myout, 16, ak_true));
        free(str);
        ak_log_set_message(str = ak_ptr_to_hexstr(in, 16, ak_true));
        free(str);
        ak_bckey_destroy(&bkey);
        return ak_false;
    }
    if (audit >= ak_log_maximum)
        ak_error_message(ak_error_ok, __func__,
                         "the one block decryption test from NIST SP 800-38A is Ok");

    /* 3. Тестируем режим простой замены согласно NIST Special Publication 800-38A */
    if ((error = ak_bckey_context_encrypt_ecb(&bkey, inlong, myout, 64)) != ak_error_ok) {
        ak_error_message_fmt(error, __func__, "wrong ecb mode encryption");
        ak_bckey_destroy(&bkey);
        return ak_false;
    }
    if (!ak_ptr_is_equal(myout, outecb, 64)) {
        ak_error_message_fmt(ak_error_not_equal_data, __func__,
                             "the ecb mode encryption test from NIST SP 800-38A is wrong");
        ak_log_set_message(str = ak_ptr_to_hexstr(myout, 64, ak_true));
        free(str);
        ak_log_set_message(str = ak_ptr_to_hexstr(outecb, 64, ak_true));
        free(str);
        ak_bckey_destroy(&bkey);
        return ak_false;
    }
    if (audit >= ak_log_maximum)
        ak_error_message(ak_error_ok, __func__,
                         "the ecb mode encryption test from NIST SP 800-38A is Ok");

    if ((error = ak_bckey_context_decrypt_ecb(&bkey, outecb, myout, 64)) != ak_error_ok) {
        ak_error_message_fmt(error, __func__, "wrong ecb mode decryption");
        ak_bckey_destroy(&bkey);
        return ak_false;
    }
    if (!ak_ptr_is_equal(myout, inlong, 64)) {
        ak_error_message_fmt(ak_error_not_equal_data, __func__,
                             "the ecb mode decryption test from NIST SP 800-38A is wrong");
        ak_log_set_message(str = ak_ptr_to_hexstr(myout, 64, ak_true));
        free(str);
        ak_log_set_message(str = ak_ptr_to_hexstr(inlong, 64, ak_true));
        free(str);
        ak_bckey_destroy(&bkey);
        return ak_false;
    }
    if (audit >= ak_log_maximum)
        ak_error_message(ak_error_ok, __func__,
                         "the ecb mode decryption test from NIST SP 800-38A is Ok");

    /* уничтожаем ключ и выходим */
    ak_bckey_destroy(&bkey);
    return ak_true;
}




