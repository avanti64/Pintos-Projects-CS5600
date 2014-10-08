#include "devices/timer.h"
#include "threads/thread.h"

void yielder();
void test_sachin();

void yielder () { 
thread_yield(); 
}
void test_sachin()
{
tid_t t1 = thread_create("first yielder", PRI_DEFAULT, yielder, NULL);
timer_sleep (10);
tid_t t2 = thread_create("second yielder", PRI_DEFAULT, yielder, NULL);

thread_yield();



}
