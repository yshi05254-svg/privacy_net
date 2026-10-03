package com.heytap.openid;

// 与 com.heytap.openid.IdentifyService（action action.com.heytap.openid.OPEN_ID_SERVICE）对接的
// 桩 AIDL：仅声明 I2 探测所需的最小方法集，不携带任何厂商实现。
interface IOpenID {
    String getSerID(in String arg0, in String arg1, in String arg2);
}
