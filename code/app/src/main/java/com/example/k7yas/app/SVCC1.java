// test815a : USAG-KOX SCVV1
package com.example.k7yas.app;

import android.os.Parcelable;
import androidx.lifecycle.MutableLiveData;

// USAG-SVCC1, Manages communication between main and service
public class SVCC1 {
    // Parcelable Event
    public static class VEvent {
        public final String action;
        public final Parcelable data;

        public VEvent(String action, Parcelable data) {
            this.action = action;
            this.data = data;
        }
    }

    // Singleton creation
    private static SVCC1 instance;
    public static synchronized SVCC1 getChan() {
        if (instance == null) instance = new SVCC1();
        return instance;
    }

    // Shared Memory, Input/Output Bus
    public final MutableLiveData<Integer>[] IntSlots = new MutableLiveData[4];
    public final MutableLiveData<Long>[] LongSlots = new MutableLiveData[4];
    public final MutableLiveData<Double>[] DoubleSlots = new MutableLiveData[4];
    public final MutableLiveData<String>[] StringSlots = new MutableLiveData[4];
    public final MutableLiveData<VEvent> ToSvcBus = new MutableLiveData<>();
    public final MutableLiveData<VEvent> ToMainBus = new MutableLiveData<>();
    private SVCC1() {
        for (int i = 0; i < 4; i++) { // init slots
            this.IntSlots[i] = new MutableLiveData<>(0);
            this.LongSlots[i] = new MutableLiveData<>(0L);
            this.DoubleSlots[i] = new MutableLiveData<>(0.0);
            this.StringSlots[i] = new MutableLiveData<>("");
        }
    }

    // Slot Update, Message Append
    public void SetInt(int index, int value) { if (index < 4) this.IntSlots[index].postValue(value); }
    public void SetLong(int index, long value) { if (index < 4) this.LongSlots[index].postValue(value); }
    public void SetDouble(int index, double value) { if (index < 4) this.DoubleSlots[index].postValue(value); }
    public void SetString(int index, String value) { if (index < 4) this.StringSlots[index].postValue(value); }
    public void SendToSvc(String action, Parcelable data) { this.ToSvcBus.postValue(new VEvent(action, data)); }
    public void SendToMain(String action, Parcelable data) { this.ToMainBus.postValue(new VEvent(action, data)); }
}
