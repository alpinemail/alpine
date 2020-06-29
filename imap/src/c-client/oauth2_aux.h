/*
 * ========================================================================
 * Copyright 2013-2020 Eduardo Chappa
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *      
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * ========================================================================
 */
#ifndef C_CLIENT_OAUTH2_AUX_INCLUDED
#define C_CLIENT_OAUTH2_AUX_INCLUDED

#define OA2_CODE_WAIT		1
#define OA2_CODE_FAIL		-1
#define OA2_CODE_SUCCESS	0

void mm_login_oauth2_c_client_method (NETMBX *, char *, char *, OAUTH2_S *, unsigned long, int *);
void oauth2deviceinfo_get_accesscode(void *, void *);

#endif /* C_CLIENT_OAUTH2_AUX_INCLUDED */

