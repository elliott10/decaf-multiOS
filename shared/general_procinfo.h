#ifndef GENERAL_PROCINFO_H_
#define GENERAL_PROCINFO_H_

#ifdef TARGET_I386
  #define T_FMT ""
  #define PI_R_EAX "eax"
  #define PI_R_ESP "esp"
/*
  #define isPrintableASCII(_x) ( ((_x & 0x80808080) == 0)   \
                                && ((_x & 0xE0E0E0E0) != 0) )
*/
#elif defined(TARGET_ARM)
  #define T_FMT ""
  #define PI_R_EAX "r0"
  #define PI_R_ESP "sp"

/*
  #define isPrintableASCII(_x) ( ((_x & 0x80808080) == 0)   \
                                && ((_x & 0xE0E0E0E0) != 0) )
*/
#else
  #define T_FMT "ll"
  #define PI_R_EAX "rax"
  #define PI_R_ESP "rsp"
/*
  #define isPrintableASCII(_x) ( ((_x & 0x8080808080808080) == 0)   \
                                && ((_x & 0xE0E0E0E0E0E0E0E0) != 0) )
*/
#endif

static inline int isPrintableASCII(target_ulong x)
{
  int i = 0;
  char c = 0;
  int ret = 0;
  
  do 
  {
    c = (x >> i) & 0xFF; //get the next character
    if ( ((c & 0x80) == 0) && ((c & 0xE0) != 0) )
    {
      ret = 1;
    }
    else if (c != 0)
    {
      return (0); //we found a non printable non NULL character so end it
    }
    i+=8; //shift it over 1 byte
  } while ( (c != 0) && (i < 64) ); //while its not the NULL character

  return (ret);
}

typedef target_ptr gva_t;
typedef target_ulong gpa_t;
typedef target_int target_pid_t;

//Here are some definitions straight from page_types.h

#define INV_ADDR ((target_ulong) -1)
#define INV_OFFSET ((target_ulong) -1)
#define INV_UINT ((target_uint) -1)

#endif /* GENERAL_PROCINFO_H_ */
