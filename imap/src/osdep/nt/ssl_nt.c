/* ========================================================================
 * Copyright 2018 Eduardo Chappa
 * Copyright 2008-2009 Mark Crispin
 * ========================================================================
 */

/*
 * Program:	SSL authentication/encryption module for Windows 9x and NT
 *
 * Author:	Mark Crispin
 *
 * Date:	22 September 1998
 * Last Edited:	8 November 2009
 *
 * Previous versions of this file were
 *
 * Copyright 1988-2008 University of Washington
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 */
#if defined(ENABLE_WINDOWS_UNIXSSL) && defined(WXPBUILD)
#include "ssl_libressl.c"
#else
#include "ssl_win.c"
#endif
