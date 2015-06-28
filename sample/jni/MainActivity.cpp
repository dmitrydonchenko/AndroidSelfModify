#include <jni.h>
#include <sys/mman.h>
#include <cstring>
#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <android/log.h>
#include <iostream>
#include <sstream>
#include <vector>

using namespace std;

#define APPNAME "MyApp"

#ifdef __cplusplus
extern "C" {
#endif

// returns a vector of the .dex and .oat file addresses
vector<pair<string, string> > getDexAddresses() {
	FILE *fp;
	char line[2048];
	vector<pair<string, string> > addresses(0);

	// open file with information about process memory
	fp = fopen("/proc/self/maps", "r");
	if (fp == NULL) {
		__android_log_print(ANDROID_LOG_VERBOSE, APPNAME,
				"Error opening proc/self/maps");
		return addresses;
	}

	// read file line by line
	while (fgets(line, 2048, fp) != NULL) {
		// search for 'dex' or 'oat'
		if (strstr(line, ".oat") != NULL || strstr(line, ".dex") != NULL) {
			__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "\n%s", line);

			// parse the line
			string linestl(line);
			string addr_begin, addr_end;
			int i;
			for(i = 0; i < linestl.length(); i++)
			{
				if(linestl[i] == '-')
					addr_begin = linestl.substr(0, i);
				if(linestl[i] == ' ')
				{
					addr_end = linestl.substr(addr_begin.length() + 1, i - addr_begin.length() - 1);
					break;
				}
			}
			addresses.push_back(make_pair(addr_begin, addr_end));
			__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "\nAddresses:");
			__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "\n%s", addr_begin.c_str());
			__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "\n%s", addr_end.c_str());
		}
	}
	return addresses;
}

JNIEXPORT jint JNICALL Java_com_example_android_market_licensing_MainActivity_makeModification(
		JNIEnv* env, jobject thiz) {

	__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "MAKE MODIFICATION BEGIN\n");

	vector<pair<string, string> > addresses = getDexAddresses();

	__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Start check\n");

	bool found = false;
	for(int i = 0; i < addresses.size(); i++)
	{
		string info_str = "Checking addresses " + addresses[i].first + " - " + addresses[i].second;
		__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "\n%s", info_str.c_str());

		char *start_ptr;
		char *end_ptr;
		long long int s, e;
		istringstream iss_start(addresses[i].first);
		iss_start >> std::hex >> s;
		istringstream iss_end(addresses[i].second);
		iss_end >> std::hex >> e;

		long long int len = e - s;
		start_ptr = (char *)s;
		end_ptr = (char *)e;
		__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "%lld", s);
		__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "%lld", e);
		__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "%lld", len);

		// set the rights to write the file
		int status = mprotect((void *) start_ptr, len,
				PROT_READ | PROT_WRITE | PROT_EXEC);
		if (status == 0) {
			__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "mprotect ok");
		} else {
			__android_log_print(ANDROID_LOG_VERBOSE, APPNAME,
					"mprotect error code:%d", status);
			continue;
		}

		//char *candidate = (char *) memchr(start_ptr, 0x14, (end_ptr - start_ptr));
		// search for method's bytes
		int cur_it = 0;
		int step = 1000;
		// byte[] methodBytes = { 0x13, 0x00, 0x2A, 0x00, 0x0F, 0x00 };
		// start check
		for(char *c = start_ptr; c < end_ptr - 5; c++)
		{
			// debug info
			if(cur_it - step >= 1000)
			{
				step = cur_it;
				//__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Current iteration: %d", cur_it);
				//__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "\n");
			}
			cur_it++;
			// method found
			if(c[0] == 0x13 && c[1] == 0x00	&&
			   c[2] == 0x2A && c[3] == 0x00	&&
			   c[4] == 0x0F && c[5] == 0x00)
			{
				__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Method was found");

				// modifying the code
				found = true;
				char src = 0x13;
				memcpy ( c + 2, &src, sizeof(char) );
				/*char src = 0x2A;
				for(int ii = 0; ii < 6; ii++)
				{
					c[ii] ^= src;
				}*/

				__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "Modification done, iteration=%d", cur_it);
				__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "0x%x ", c[0]);
				__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "0x%x ", c[1]);
				__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "0x%x ", c[2]);
				__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "0x%x ", c[3]);
				__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "0x%x ", c[4]);
				__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "0x%x", c[5]);
				found = true;
				break;
			}
		}
		if(found)
		{
			status = mprotect((void *) start_ptr, len,
							PROT_READ | PROT_EXEC);
			if (status == 0) {
				__android_log_print(ANDROID_LOG_VERBOSE, APPNAME, "mprotect back ok");
			} else {
				__android_log_print(ANDROID_LOG_VERBOSE, APPNAME,
						"mprotect error code:%d", status);
			}
			break;
		}
	}
	return 0;
}

#ifdef __cplusplus
}
#endif
