package com.cherepavel.vpndetector.util

import java.util.Enumeration

fun <T> Enumeration<T>.toListSafe(): List<T> {
    val result = mutableListOf<T>()
    while (hasMoreElements()) {
        result.add(nextElement())
    }
    return result
}
