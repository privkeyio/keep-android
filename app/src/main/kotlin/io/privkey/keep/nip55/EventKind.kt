package io.privkey.keep.nip55

import android.content.Context
import io.privkey.keep.R

object EventKind {
    fun name(context: Context, kind: Int): String {
        val resId = when (kind) {
            0 -> R.string.event_kind_0
            1 -> R.string.event_kind_1
            2 -> R.string.event_kind_2
            3 -> R.string.event_kind_3
            4 -> R.string.event_kind_4
            5 -> R.string.event_kind_5
            6 -> R.string.event_kind_6
            7 -> R.string.event_kind_7
            8 -> R.string.event_kind_8
            9 -> R.string.event_kind_9
            10 -> R.string.event_kind_10
            11 -> R.string.event_kind_11
            12 -> R.string.event_kind_12
            13 -> R.string.event_kind_13
            14 -> R.string.event_kind_14
            15 -> R.string.event_kind_15
            16 -> R.string.event_kind_16
            17 -> R.string.event_kind_17
            20 -> R.string.event_kind_20
            21 -> R.string.event_kind_21
            22 -> R.string.event_kind_22
            24 -> R.string.event_kind_24
            30 -> R.string.event_kind_30
            31 -> R.string.event_kind_31
            32 -> R.string.event_kind_32
            33 -> R.string.event_kind_33
            40 -> R.string.event_kind_40
            41 -> R.string.event_kind_41
            42 -> R.string.event_kind_42
            43 -> R.string.event_kind_43
            44 -> R.string.event_kind_44
            62 -> R.string.event_kind_62
            64 -> R.string.event_kind_64
            443 -> R.string.event_kind_443
            444 -> R.string.event_kind_444
            445 -> R.string.event_kind_445
            818 -> R.string.event_kind_818
            1018 -> R.string.event_kind_1018
            1021 -> R.string.event_kind_1021
            1022 -> R.string.event_kind_1022
            1040 -> R.string.event_kind_1040
            1059 -> R.string.event_kind_1059
            1063 -> R.string.event_kind_1063
            1068 -> R.string.event_kind_1068
            1111 -> R.string.event_kind_1111
            1222 -> R.string.event_kind_1222
            1244 -> R.string.event_kind_1244
            1311 -> R.string.event_kind_1311
            1337 -> R.string.event_kind_1337
            1617 -> R.string.event_kind_1617
            1618 -> R.string.event_kind_1618
            1619 -> R.string.event_kind_1619
            1621 -> R.string.event_kind_1621
            1622 -> R.string.event_kind_1622
            in 1630..1633 -> R.string.event_kind_status
            1971 -> R.string.event_kind_1971
            1984 -> R.string.event_kind_1984
            1985 -> R.string.event_kind_1985
            1986 -> R.string.event_kind_1986
            1987 -> R.string.event_kind_1987
            2003 -> R.string.event_kind_2003
            2004 -> R.string.event_kind_2004
            2022 -> R.string.event_kind_2022
            4550 -> R.string.event_kind_4550
            in 5000..5999 -> R.string.event_kind_job_request
            in 6000..6999 -> R.string.event_kind_job_result
            7000 -> R.string.event_kind_7000
            7374 -> R.string.event_kind_7374
            7375 -> R.string.event_kind_7375
            7376 -> R.string.event_kind_7376
            7516 -> R.string.event_kind_7516
            7517 -> R.string.event_kind_7517
            8000 -> R.string.event_kind_8000
            8001 -> R.string.event_kind_8001
            9000 -> R.string.event_kind_9000
            9001 -> R.string.event_kind_9001
            9002 -> R.string.event_kind_9002
            9003 -> R.string.event_kind_9003
            9004 -> R.string.event_kind_9004
            9005 -> R.string.event_kind_9005
            9006 -> R.string.event_kind_9006
            9007 -> R.string.event_kind_9007
            9021 -> R.string.event_kind_9021
            in 9000..9030 -> R.string.event_kind_group_control_events
            9041 -> R.string.event_kind_9041
            9321 -> R.string.event_kind_9321
            9467 -> R.string.event_kind_9467
            9734 -> R.string.event_kind_9734
            9735 -> R.string.event_kind_9735
            9802 -> R.string.event_kind_9802
            10000 -> R.string.event_kind_10000
            10001 -> R.string.event_kind_10001
            10002 -> R.string.event_kind_10002
            10003 -> R.string.event_kind_10003
            10004 -> R.string.event_kind_10004
            10005 -> R.string.event_kind_10005
            10006 -> R.string.event_kind_10006
            10007 -> R.string.event_kind_10007
            10009 -> R.string.event_kind_10009
            10012 -> R.string.event_kind_10012
            10013 -> R.string.event_kind_10013
            10015 -> R.string.event_kind_10015
            10019 -> R.string.event_kind_10019
            10020 -> R.string.event_kind_10020
            10030 -> R.string.event_kind_10030
            10050 -> R.string.event_kind_10050
            10051 -> R.string.event_kind_10051
            10063 -> R.string.event_kind_10063
            10096 -> R.string.event_kind_10096
            10101 -> R.string.event_kind_10101
            10102 -> R.string.event_kind_10102
            10166 -> R.string.event_kind_10166
            10312 -> R.string.event_kind_10312
            10377 -> R.string.event_kind_10377
            11111 -> R.string.event_kind_11111
            13194 -> R.string.event_kind_13194
            13534 -> R.string.event_kind_13534
            14388 -> R.string.event_kind_14388
            17375 -> R.string.event_kind_17375
            21000 -> R.string.event_kind_21000
            22242 -> R.string.event_kind_22242
            22456 -> R.string.event_kind_22456
            23194 -> R.string.event_kind_23194
            23195 -> R.string.event_kind_23195
            24133 -> R.string.event_kind_24133
            24242 -> R.string.event_kind_24242
            25050 -> R.string.event_kind_25050
            27235 -> R.string.event_kind_27235
            28934 -> R.string.event_kind_28934
            28935 -> R.string.event_kind_28935
            28936 -> R.string.event_kind_28936
            30000 -> R.string.event_kind_30000
            30001 -> R.string.event_kind_30001
            30002 -> R.string.event_kind_30002
            30003 -> R.string.event_kind_30003
            30004 -> R.string.event_kind_30004
            30005 -> R.string.event_kind_30005
            30006 -> R.string.event_kind_30006
            30007 -> R.string.event_kind_30007
            30008 -> R.string.event_kind_30008
            30009 -> R.string.event_kind_30009
            30015 -> R.string.event_kind_30015
            30017 -> R.string.event_kind_30017
            30018 -> R.string.event_kind_30018
            30019 -> R.string.event_kind_30019
            30020 -> R.string.event_kind_30020
            30023 -> R.string.event_kind_30023
            30024 -> R.string.event_kind_30024
            30030 -> R.string.event_kind_30030
            30040 -> R.string.event_kind_30040
            30041 -> R.string.event_kind_30041
            30063 -> R.string.event_kind_30063
            30078 -> R.string.event_kind_30078
            30166 -> R.string.event_kind_30166
            30267 -> R.string.event_kind_30267
            30311 -> R.string.event_kind_30311
            30312 -> R.string.event_kind_30312
            30313 -> R.string.event_kind_30313
            30315 -> R.string.event_kind_30315
            30382 -> R.string.event_kind_30382
            30383 -> R.string.event_kind_30383
            30384 -> R.string.event_kind_30384
            30388 -> R.string.event_kind_30388
            30402 -> R.string.event_kind_30402
            30403 -> R.string.event_kind_30403
            30617 -> R.string.event_kind_30617
            30618 -> R.string.event_kind_30618
            30818 -> R.string.event_kind_30818
            30819 -> R.string.event_kind_30819
            31234 -> R.string.event_kind_31234
            31388 -> R.string.event_kind_31388
            31890 -> R.string.event_kind_31890
            31922 -> R.string.event_kind_31922
            31923 -> R.string.event_kind_31923
            31924 -> R.string.event_kind_31924
            31925 -> R.string.event_kind_31925
            31989 -> R.string.event_kind_31989
            31990 -> R.string.event_kind_31990
            32267 -> R.string.event_kind_32267
            32388 -> R.string.event_kind_32388
            33388 -> R.string.event_kind_33388
            34235 -> R.string.event_kind_34235
            34236 -> R.string.event_kind_34236
            34388 -> R.string.event_kind_34388
            34550 -> R.string.event_kind_34550
            37375 -> R.string.event_kind_37375
            37516 -> R.string.event_kind_37516
            38172 -> R.string.event_kind_38172
            38173 -> R.string.event_kind_38173
            38383 -> R.string.event_kind_38383
            39000 -> R.string.event_kind_39000
            39001 -> R.string.event_kind_39001
            39002 -> R.string.event_kind_39002
            in 39003..39009 -> R.string.event_kind_group_metadata_events
            39089 -> R.string.event_kind_39089
            39092 -> R.string.event_kind_39092
            39701 -> R.string.event_kind_39701
            10000300 -> R.string.event_kind_10000300
            else -> return context.getString(R.string.event_kind_unknown, kind)
        }
        return context.getString(resId)
    }

    fun displayName(context: Context, kind: Int): String {
        val named = name(context, kind)
        val unknown = context.getString(R.string.event_kind_unknown, kind)
        return if (named == unknown) named else context.getString(R.string.event_kind_with_number, named, kind)
    }
}
