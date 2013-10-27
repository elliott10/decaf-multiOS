/*
 Copyright (C) <2012> <Syracuse System Security (Sycure) Lab>

 DECAF is based on QEMU, a whole-system emulator. You can redistribute
 and modify it under the terms of the GNU GPL, version 3 or later,
 but it is made available WITHOUT ANY WARRANTY. See the top-level
 README file for more details.

 For more information about DECAF and other softwares, see our
 web site at:
 http://sycurelab.ecs.syr.edu/

 If you have any questions about DECAF,please post it on
 http://code.google.com/p/decaf-platform/
*/

/*
   linux_readelf.c
   Extract elf information from modules inside DECAF, based on readelf from binutils
   Different from the original readelf, we do not need to support both x86 and x64 at
   the same time, nor do we need to support differnt platform neither.  We assume the
   target platform's architecture is the one we are going to read.

   by Kevin Wang, Sep 2013
*/


#include <inttypes.h>
#include <string>
#include <list>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>
#include <tr1/unordered_map>
#include <tr1/unordered_set>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <queue>
#include <sys/time.h>
#include <math.h>
#include <glib.h>
#include <mcheck.h>
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */
#include "cpu.h"
#include "config.h"
#include "hw/hw.h" // AWH

#ifdef __cplusplus
};
#endif /* __cplusplus */

#include "hookapi.h"
#include "function_map.h"
#include "shared/procmod.h"
#include "shared/vmi.h"
#include "DECAF_main.h"
#include "DECAF_target.h"
#include "shared/utils/SimpleCallback.h"

#if HOST_LONG_BITS == 64
/* Define BFD64 here, even if our default architecture is 32 bit ELF
   as this will allow us to read in and parse 64bit and 32bit ELF files.
   Only do this if we believe that the compiler can support a 64 bit
   data type.  For now we only rely on GCC being able to do this.  */
#define BFD64
#endif

#include "bfd.h"
#include "elf/common.h"
#include "elf/external.h"
#include "elf/internal.h"

/* The following headers use the elf/reloc-macros.h file to
   automatically generate relocation recognition functions
   such as elf_mips_reloc_type()  */

#define RELOC_MACROS_GEN_FUNC

#ifdef TARGET_I386
#include "elf/i386.h"
#elif defined(TARGET_ARM)
#include "elf/arm.h"
#elif defined(TARGET_X86_64)
#include "elf/x86-64.h"
#endif

#if TARGET_LONG_BITS == 64
typedef uint64_t elf_vma;
typedef Elf64_External_Rel Elf_External_Rel;
typedef Elf64_External_Rela Elf_External_Rela;
typedef Elf64_External_Sym Elf_External_Sym;
typedef Elf64_External_Phdr Elf_External_Phdr;
typedef Elf64_External_Shdr Elf_External_Shdr;
typedef Elf64_External_Ehdr Elf_External_Ehdr;
typedef Elf64_External_Dyn Elf_External_Dyn;
#else
typedef uint32_t elf_vma;
typedef Elf32_External_Rel Elf_External_Rel;
typedef Elf32_External_Rela Elf_External_Rela;
typedef Elf32_External_Sym Elf_External_Sym;
typedef Elf32_External_Phdr Elf_External_Phdr;
typedef Elf32_External_Shdr Elf_External_Shdr;
typedef Elf32_External_Ehdr Elf_External_Ehdr;
typedef Elf32_External_Dyn Elf_External_Dyn;
#endif

// define the elf data we need to retrive
typedef struct {
	Elf_Internal_Sym * dynamic_symbols;
	Elf_Internal_Syminfo * dynamic_syminfo;
	Elf_Internal_Ehdr elf_header;
	Elf_Internal_Shdr * section_headers;
	Elf_Internal_Phdr * program_headers;
	Elf_Internal_Dyn *  dynamic_section;
	Elf_Internal_Shdr * symtab_shndx_hdr;
} elfInfo;

static long archive_file_offset;
static unsigned long archive_file_size;
static unsigned long dynamic_addr;
static bfd_size_type dynamic_size;
static unsigned int dynamic_nent;
static char * dynamic_strings;
static unsigned long dynamic_strings_length;
static char * string_table;
static unsigned long string_table_length;
static unsigned long num_dynamic_syms;
static Elf_Internal_Sym * dynamic_symbols;
static Elf_Internal_Syminfo * dynamic_syminfo;
static unsigned long dynamic_syminfo_offset;
static unsigned int dynamic_syminfo_nent;
static bfd_vma dynamic_info[DT_ENCODING];
static bfd_vma dynamic_info_DT_GNU_HASH;
static bfd_vma version_info[16];
static Elf_Internal_Ehdr elf_header;
static Elf_Internal_Shdr * section_headers;
static Elf_Internal_Phdr * program_headers;
static Elf_Internal_Dyn *  dynamic_section;
static Elf_Internal_Shdr * symtab_shndx_hdr;
static int do_dynamic;
static int do_syms;
static int do_dyn_syms;
static int do_reloc;
static int do_sections;
static int do_section_groups;
static int do_section_details;
static int do_segments;
static int do_unwind;
static int do_using_dynamic;
static int do_header;
static int do_dump;
static int do_version;
static int do_histogram;
static int do_debugging;
static int do_arch;
static int do_notes;
static int do_archive_index;
static int is_32bit_elf;

static size_t group_count;
static struct group * section_groups;
static struct group ** section_headers_groups;


#define SEEK_SET 0
#define ARRAY_SIZE(a) (sizeof (a) / sizeof ((a)[0]))

typedef unsigned char dump_type;

/* A linked list of the section names for which dumps were requested.  */
struct dump_list_entry
{
	char * name;
	dump_type type;
	struct dump_list_entry * next;
};
static struct dump_list_entry * dump_sects_byname;

/* A dynamic array of flags indicating for which sections a dump
   has been requested via command line switches.  */
static dump_type *   cmdline_dump_sects = NULL;
static unsigned int  num_cmdline_dump_sects = 0;

/* A dynamic array of flags indicating for which sections a dump of
   some kind has been requested.  It is reset on a per-object file
   basis and then initialised from the cmdline_dump_sects array,
   the results of interpreting the -w switch, and the
   dump_sects_byname list.  */
static dump_type *   dump_sects = NULL;
static unsigned int  num_dump_sects = 0;

/* How to print a vma value.  */
typedef enum print_mode
{
	HEX,
	DEC,
	DEC_5,
	UNSIGNED,
	PREFIX_HEX,
	FULL_HEX,
	LONG_HEX
}
print_mode;

#define UNKNOWN -1

#define BYTE_PUT(field, val)	byte_put (field, val, sizeof (field))
#define BYTE_GET(field)		byte_get (field, sizeof (field))
#define BYTE_GET_SIGNED(field)	byte_get_signed (field, sizeof (field))

#define SECTION_NAME(X)						\
  ((X) == NULL ? ("<none>")					\
   : string_table == NULL ? ("<no-name>")			\
   : ((X)->sh_name >= string_table_length ? ("<corrupt>")	\
  : string_table + (X)->sh_name))

#define DT_VERSIONTAGIDX(tag)	(DT_VERNEEDNUM - (tag))	/* Reverse order!  */

#define VALID_DYNAMIC_NAME(offset)	((dynamic_strings != NULL) && (offset < dynamic_strings_length))
/* GET_DYNAMIC_NAME asssumes that VALID_DYNAMIC_NAME has
   already been called and verified that the string exists.  */
#define GET_DYNAMIC_NAME(offset)	(dynamic_strings + offset)

#define REMOVE_ARCH_BITS(ADDR)			\
  do						\
    {						\
      if (elf_header.e_machine == EM_ARM)	\
	(ADDR) &= ~1;				\
    }						\
  while (0)


/* Retrieve NMEMB structures, each SIZE bytes long from FILE starting at OFFSET.
   Put the retrieved data into VAR, if it is not NULL.  Otherwise allocate a buffer
   using malloc and fill that.  In either case return the pointer to the start of
   the retrieved data or NULL if something went wrong.  If something does go wrong
   emit an error message using REASON as part of the context.  */
static void *
cmalloc (size_t nmemb, size_t size)
{
  /* Check for overflow.  */
  if (nmemb >= ~(size_t) 0 / size)
    return NULL;
  else
    return malloc (nmemb * size);
}

static void *
get_data (void * var, FILE * file, long offset, size_t size, size_t nmemb,
		  const char * reason)
{
	void * mvar;

	if (size == 0 || nmemb == 0)
		return NULL;

	if (fseek (file, archive_file_offset + offset, SEEK_SET))
	{
		printf (("Unable to seek to 0x%lx for %s\n"),
			   (unsigned long) archive_file_offset + offset, reason);
		return NULL;
	}

	mvar = var;
	if (mvar == NULL)
	{
		/* Check for overflow.  */
		if (nmemb < (~(size_t) 0 - 1) / size)
			/* + 1 so that we can '\0' terminate invalid string table sections.  */
			mvar = malloc (size * nmemb + 1);

		if (mvar == NULL)
		{
			printf (("Out of memory allocating 0x%lx bytes for %s\n"),
				   (unsigned long)(size * nmemb), reason);
			return NULL;
		}

		((char *) mvar)[size * nmemb] = '\0';
	}

	if (fread (mvar, size, nmemb, file) != nmemb)
	{
		printf (("Unable to read in 0x%lx bytes of %s\n"),
			   (unsigned long)(size * nmemb), reason);
		if (mvar != var)
			free (mvar);
		return NULL;
	}

	return mvar;
}



void (*byte_put) (unsigned char *, elf_vma, int);

void
byte_put_little_endian (unsigned char * field, elf_vma value, int size)
{
  switch (size)
    {
    case 8:
      field[7] = (((value >> 24) >> 24) >> 8) & 0xff;
      field[6] = ((value >> 24) >> 24) & 0xff;
      field[5] = ((value >> 24) >> 16) & 0xff;
      field[4] = ((value >> 24) >> 8) & 0xff;
      /* Fall through.  */
    case 4:
      field[3] = (value >> 24) & 0xff;
      /* Fall through.  */
    case 3:
      field[2] = (value >> 16) & 0xff;
      /* Fall through.  */
    case 2:
      field[1] = (value >> 8) & 0xff;
      /* Fall through.  */
    case 1:
      field[0] = value & 0xff;
      break;

    default:
      printf ("Unhandled data length: %d\n", size);
      abort ();
    }
}

void
byte_put_big_endian (unsigned char * field, elf_vma value, int size)
{
  switch (size)
    {
    case 8:
      field[7] = value & 0xff;
      field[6] = (value >> 8) & 0xff;
      field[5] = (value >> 16) & 0xff;
      field[4] = (value >> 24) & 0xff;
      value >>= 16;
      value >>= 16;
      /* Fall through.  */
    case 4:
      field[3] = value & 0xff;
      value >>= 8;
      /* Fall through.  */
    case 3:
      field[2] = value & 0xff;
      value >>= 8;
      /* Fall through.  */
    case 2:
      field[1] = value & 0xff;
      value >>= 8;
      /* Fall through.  */
    case 1:
      field[0] = value & 0xff;
      break;

    default:
      printf("Unhandled data length: %d\n", size);
      abort ();
    }
}

elf_vma (*byte_get) (unsigned char *, int);

elf_vma
byte_get_little_endian (unsigned char *field, int size)
{
  switch (size)
    {
    case 1:
      return *field;

    case 2:
      return  ((unsigned int) (field[0]))
	|    (((unsigned int) (field[1])) << 8);

    case 3:
      return  ((unsigned long) (field[0]))
	|    (((unsigned long) (field[1])) << 8)
	|    (((unsigned long) (field[2])) << 16);

    case 4:
      return  ((unsigned long) (field[0]))
	|    (((unsigned long) (field[1])) << 8)
	|    (((unsigned long) (field[2])) << 16)
	|    (((unsigned long) (field[3])) << 24);

    case 8:
      if (sizeof (elf_vma) == 8)
	return  ((elf_vma) (field[0]))
	  |    (((elf_vma) (field[1])) << 8)
	  |    (((elf_vma) (field[2])) << 16)
	  |    (((elf_vma) (field[3])) << 24)
	  |    (((elf_vma) (field[4])) << 32)
	  |    (((elf_vma) (field[5])) << 40)
	  |    (((elf_vma) (field[6])) << 48)
	  |    (((elf_vma) (field[7])) << 56);
      else if (sizeof (elf_vma) == 4)
	/* We want to extract data from an 8 byte wide field and
	   place it into a 4 byte wide field.  Since this is a little
	   endian source we can just use the 4 byte extraction code.  */
	return  ((unsigned long) (field[0]))
	  |    (((unsigned long) (field[1])) << 8)
	  |    (((unsigned long) (field[2])) << 16)
	  |    (((unsigned long) (field[3])) << 24);

    default:
      printf("Unhandled data length: %d\n", size);
      abort ();
    }
}

elf_vma
byte_get_big_endian (unsigned char *field, int size)
{
  switch (size)
    {
    case 1:
      return *field;

    case 2:
      return ((unsigned int) (field[1])) | (((int) (field[0])) << 8);

    case 3:
      return ((unsigned long) (field[2]))
	|   (((unsigned long) (field[1])) << 8)
	|   (((unsigned long) (field[0])) << 16);

    case 4:
      return ((unsigned long) (field[3]))
	|   (((unsigned long) (field[2])) << 8)
	|   (((unsigned long) (field[1])) << 16)
	|   (((unsigned long) (field[0])) << 24);

    case 8:
      if (sizeof (elf_vma) == 8)
	return ((elf_vma) (field[7]))
	  |   (((elf_vma) (field[6])) << 8)
	  |   (((elf_vma) (field[5])) << 16)
	  |   (((elf_vma) (field[4])) << 24)
	  |   (((elf_vma) (field[3])) << 32)
	  |   (((elf_vma) (field[2])) << 40)
	  |   (((elf_vma) (field[1])) << 48)
	  |   (((elf_vma) (field[0])) << 56);
      else if (sizeof (elf_vma) == 4)
	{
	  /* Although we are extracing data from an 8 byte wide field,
	     we are returning only 4 bytes of data.  */
	  field += 4;
	  return ((unsigned long) (field[3]))
	    |   (((unsigned long) (field[2])) << 8)
	    |   (((unsigned long) (field[1])) << 16)
	    |   (((unsigned long) (field[0])) << 24);
	}

    default:
      printf("Unhandled data length: %d\n", size);
      abort ();
    }
}

elf_vma
byte_get_signed (unsigned char *field, int size)
{
  elf_vma x = byte_get (field, size);

  switch (size)
    {
    case 1:
      return (x ^ 0x80) - 0x80;
    case 2:
      return (x ^ 0x8000) - 0x8000;
    case 4:
      return (x ^ 0x80000000) - 0x80000000;
    case 8:
      return x;
    default:
      abort ();
    }
}

/* Print a VMA value.  */

static int
print_vma (bfd_vma vma, print_mode mode)
{
	int nc = 0;

	switch (mode)
	{
	case FULL_HEX:
		nc = printf ("0x");
		/* Drop through.  */

	case LONG_HEX:
#ifdef BFD64
      if (is_32bit_elf)
	return nc + printf ("%8.8" BFD_VMA_FMT "x", vma);
#endif
		printf_vma (vma);
		return nc + 16;

	case DEC_5:
		if (vma <= 99999)
			return printf ("%5" BFD_VMA_FMT "d", vma);
		/* Drop through.  */

	case PREFIX_HEX:
		nc = printf ("0x");
		/* Drop through.  */

	case HEX:
		return nc + printf ("%" BFD_VMA_FMT "x", vma);

	case DEC:
		return printf ("%" BFD_VMA_FMT "d", vma);

	case UNSIGNED:
		return printf ("%" BFD_VMA_FMT "u", vma);
	}
	return 0;
}

/* Display a symbol on stdout.  Handles the display of control characters and
   multibye characters.

   Display at most abs(WIDTH) characters, truncating as necessary, unless 1 is true.

   If WIDTH is negative then ensure that the output is at least (- WIDTH) characters,
   padding as necessary.

   Returns the number of emitted characters.  */


static unsigned int
print_symbol (int width, const char *symbol)
{
	printf("%s", symbol);
	return width;
}

#if 0
static unsigned int
print_symbol (int width, const char *symbol)
{
	bfd_boolean extra_padding = FALSE;
	int num_printed = 0;
	mbstate_t state;
	int width_remaining;

	if (width < 0)
	{
		/* Keep the width positive.  This also helps.  */
		width = - width;
		extra_padding = TRUE;
	}

	if (1)
		/* Set the remaining width to a very large value.
		   This simplifies the code below.  */
		width_remaining = INT_MAX;
	else
		width_remaining = width;

	/* Initialise the multibyte conversion state.  */
	memset (& state, 0, sizeof (state));

	while (width_remaining)
	{
		size_t  n;
		wchar_t w;
		const char c = *symbol++;

		if (c == 0)
			break;

		/* Do not print control characters directly as they can affect terminal
		settings.  Such characters usually appear in the names generated
		 by the assembler for local labels.  */
		if (ISCNTRL (c))
		{
			if (width_remaining < 2)
				break;

			printf ("^%c", c + 0x40);
			width_remaining -= 2;
			num_printed += 2;
		}
		else if (ISPRINT (c))
		{
			putchar (c);
			width_remaining --;
			num_printed ++;
		}
		else
		{
			/* Let printf do the hard work of displaying multibyte characters.  */
			printf ("%.1s", symbol - 1);
			width_remaining --;
			num_printed ++;

			/* Try to find out how many bytes made up the character that was
			   just printed.  Advance the symbol pointer past the bytes that
			   were displayed.  */
			n = mbrtowc (& w, symbol - 1, MB_CUR_MAX, & state);
			if (n != (size_t) -1 && n != (size_t) -2 && n > 0)
				symbol += (n - 1);
		}
	}

	if (extra_padding && num_printed < width)
	{
		/* Fill in the remaining spaces.  */
		printf ("%-*s", width - num_printed, " ");
		num_printed = width;
	}

	return num_printed;
}

/* Return a pointer to section NAME, or NULL if no such section exists.  */

static Elf_Internal_Shdr *
find_section (const char * name)
{
	unsigned int i;

	for (i = 0; i < elf_header.e_shnum; i++)
		if (streq (SECTION_NAME (section_headers + i), name))
			return section_headers + i;

	return NULL;
}

/* Return a pointer to a section containing ADDR, or NULL if no such
   section exists.  */

static Elf_Internal_Shdr *
find_section_by_address (bfd_vma addr)
{
	unsigned int i;

	for (i = 0; i < elf_header.e_shnum; i++)
	{
		Elf_Internal_Shdr *sec = section_headers + i;
		if (addr >= sec->sh_addr && addr < sec->sh_addr + sec->sh_size)
			return sec;
	}

	return NULL;
}

/* Read an unsigned LEB128 encoded value from p.  Set *PLEN to the number of
   bytes read.  */

static unsigned long
read_uleb128 (unsigned char *data, unsigned int *length_return)
{
	return read_leb128 (data, length_return, 0);
}
/* Guess the relocation size commonly used by the specific machines.  */
#endif

static int
guess_is_rela (unsigned int e_machine)
{
	switch (e_machine)
	{
		/* Targets that use REL relocations.  */
	default:
	case EM_386:
	case EM_ARM:
		return FALSE;

		/* Targets that use RELA relocations.  */
	case EM_X86_64:
		return TRUE;
	}
}
#if 1
static int
slurp_rela_relocs (FILE * file,
				   unsigned long rel_offset,
				   unsigned long rel_size,
				   Elf_Internal_Rela ** relasp,
				   unsigned long * nrelasp)
{
	Elf_Internal_Rela * relas;
	unsigned long nrelas;
	unsigned int i;

		Elf_External_Rela * erelas;

		erelas = (Elf_External_Rela *) get_data (NULL, file, rel_offset, 1,
				 rel_size, ("64-bit relocation data"));
		if (!erelas)
			return 0;

		nrelas = rel_size / sizeof (Elf_External_Rela);

		relas = (Elf_Internal_Rela *) cmalloc (nrelas,
											   sizeof (Elf_Internal_Rela));

		if (relas == NULL)
		{
			free (erelas);
			printf (("out of memory parsing relocs\n"));
			return 0;
		}

		for (i = 0; i < nrelas; i++)
		{
			relas[i].r_offset = BYTE_GET (erelas[i].r_offset);
			relas[i].r_info   = BYTE_GET (erelas[i].r_info);
			relas[i].r_addend = BYTE_GET_SIGNED (erelas[i].r_addend);

		}

		free (erelas);

	*relasp = relas;
	*nrelasp = nrelas;
	return 1;
}

static int
slurp_rel_relocs (FILE * file,
				  unsigned long rel_offset,
				  unsigned long rel_size,
				  Elf_Internal_Rela ** relsp,
				  unsigned long * nrelsp)
{
	Elf_Internal_Rela * rels;
	unsigned long nrels;
	unsigned int i;
		Elf_External_Rel * erels;

		erels = (Elf_External_Rel *) get_data (NULL, file, rel_offset, 1,
				rel_size, ("64-bit relocation data"));
		if (!erels)
			return 0;

		nrels = rel_size / sizeof (Elf_External_Rel);

		rels = (Elf_Internal_Rela *) cmalloc (nrels, sizeof (Elf_Internal_Rela));

		if (rels == NULL)
		{
			free (erels);
			printf (("out of memory parsing relocs\n"));
			return 0;
		}

		for (i = 0; i < nrels; i++)
		{
			rels[i].r_offset = BYTE_GET (erels[i].r_offset);
			rels[i].r_info   = BYTE_GET (erels[i].r_info);
			rels[i].r_addend = 0;
		}

		free (erels);

	*relsp = rels;
	*nrelsp = nrels;
	return 1;
}

/* Returns the reloc type extracted from the reloc info field.  */

static unsigned int
get_reloc_type (bfd_vma reloc_info)
{
#if TARGET_LONG_BITS == 32
	return ELF32_R_TYPE (reloc_info);
#else
	return ELF64_R_TYPE (reloc_info);
#endif
}

/* Return the symbol index extracted from the reloc info field.  */

static bfd_vma
get_reloc_symindex (bfd_vma reloc_info)
{
#if TARGET_LONG_BITS == 32
	return ELF32_R_SYM (reloc_info);
#else
	return ELF64_R_SYM (reloc_info);
#endif
}

/* Display the contents of the relocation data found at the specified
   offset.  */

#endif
static void
dump_relocations (FILE * file,
				  unsigned long rel_offset,
				  unsigned long rel_size,
				  Elf_Internal_Sym * symtab,
				  unsigned long nsyms,
				  char * strtab,
				  unsigned long strtablen,
				  int is_rela)
{
	unsigned int i;
	Elf_Internal_Rela * rels;

	if (is_rela == UNKNOWN)
		is_rela = guess_is_rela (elf_header.e_machine);

#if 0
	if (is_rela)
	{
		if (!slurp_rela_relocs (file, rel_offset, rel_size, &rels, &rel_size))
			return;
	}
	else
	{
		if (!slurp_rel_relocs (file, rel_offset, rel_size, &rels, &rel_size))
			return;
	}

	if (is_32bit_elf)
	{
		if (is_rela)
		{
			if (1)
				printf ((" Offset     Info    Type                Sym. Value  Symbol's Name + Addend\n"));
			else
				printf ((" Offset     Info    Type            Sym.Value  Sym. Name + Addend\n"));
		}
		else
		{
			if (1)
				printf ((" Offset     Info    Type                Sym. Value  Symbol's Name\n"));
			else
				printf ((" Offset     Info    Type            Sym.Value  Sym. Name\n"));
		}
	}
	else
	{
		if (is_rela)
		{
			if (1)
				printf (("    Offset             Info             Type               Symbol's Value  Symbol's Name + Addend\n"));
			else
				printf (("  Offset          Info           Type           Sym. Value    Sym. Name + Addend\n"));
		}
		else
		{
			if (1)
				printf (("    Offset             Info             Type               Symbol's Value  Symbol's Name\n"));
			else
				printf (("  Offset          Info           Type           Sym. Value    Sym. Name\n"));
		}
	}

	for (i = 0; i < rel_size; i++)
	{
		const char * rtype;
		bfd_vma offset;
		bfd_vma inf;
		bfd_vma symtab_index;
		bfd_vma type;

		offset = rels[i].r_offset;
		inf    = rels[i].r_info;

		type = get_reloc_type (inf);
		symtab_index = get_reloc_symindex  (inf);

		if (is_32bit_elf)
		{
			printf ("%8.8lx  %8.8lx ",
					(unsigned long) offset & 0xffffffff,
					(unsigned long) inf & 0xffffffff);
		}
		else
		{
#if BFD_HOST_64BIT_LONG
			printf (1
					? "%16.16lx  %16.16lx "
					: "%12.12lx  %12.12lx ",
					offset, inf);
#elif BFD_HOST_64BIT_LONG_LONG
#ifndef __MSVCRT__
			printf (1
					? "%16.16llx  %16.16llx "
					: "%12.12llx  %12.12llx ",
					offset, inf);
#else
			printf (1
					? "%16.16I64x  %16.16I64x "
					: "%12.12I64x  %12.12I64x ",
					offset, inf);
#endif
#else
			printf (1
					? "%8.8lx%8.8lx  %8.8lx%8.8lx "
					: "%4.4lx%8.8lx  %4.4lx%8.8lx ",
					_bfd_int64_high (offset),
					_bfd_int64_low (offset),
					_bfd_int64_high (inf),
					_bfd_int64_low (inf));
#endif
		}

		switch (elf_header.e_machine)
		{
		default:
			rtype = NULL;
			break;
		case EM_386:
			rtype = elf_i386_reloc_type (type);
			break;


		case EM_ARM:
			rtype = elf_arm_reloc_type (type);
			break;

		case EM_X86_64:
			rtype = elf_x86_64_reloc_type (type);
			break;

		}

		if (rtype == NULL)
			printf (("unrecognized: %-7lx"), (unsigned long) type & 0xffffffff);
		else
			printf (1 ? "%-22.22s" : "%-17.17s", rtype);

		if (symtab_index)
		{
			if (symtab == NULL || symtab_index >= nsyms)
				printf ((" bad symbol index: %08lx"), (unsigned long) symtab_index);
			else
			{
				Elf_Internal_Sym * psym;

				psym = symtab + symtab_index;

				printf (" ");

				if (ELF_ST_TYPE (psym->st_info) == STT_GNU_IFUNC)
				{
					const char * name;
					unsigned int len;
					unsigned int width = is_32bit_elf ? 8 : 14;

					/* Relocations against GNU_IFUNC symbols do not use the value
					   of the symbol as the address to relocate against.  Instead
					   they invoke the function named by the symbol and use its
					   result as the address for relocation.

					   To indicate this to the user, do not display the value of
					   the symbol in the "Symbols's Value" field.  Instead show
					   its name followed by () as a hint that the symbol is
					   invoked.  */

					if (strtab == NULL
							|| psym->st_name == 0
							|| psym->st_name >= strtablen)
						name = "??";
					else
						name = strtab + psym->st_name;

					len = print_symbol (width, name);
					printf ("()%-*s", len <= width ? (width + 1) - len : 1, " ");
				}
				else
				{
					print_vma (psym->st_value, LONG_HEX);

					printf (is_32bit_elf ? "   " : " ");
				}

				if (psym->st_name == 0)
				{
					const char * sec_name = "<null>";
					char name_buf[40];

					if (ELF_ST_TYPE (psym->st_info) == STT_SECTION)
					{
						if (psym->st_shndx < elf_header.e_shnum)
							sec_name
								= SECTION_NAME (section_headers + psym->st_shndx);
						else if (psym->st_shndx == SHN_ABS)
							sec_name = "ABS";
						else if (psym->st_shndx == SHN_COMMON)
							sec_name = "COMMON";
						else if ((elf_header.e_machine == EM_X86_64)
								 && psym->st_shndx == SHN_X86_64_LCOMMON)
							sec_name = "LARGE_COMMON";
						else
						{
							sprintf (name_buf, "<section 0x%x>",
									 (unsigned int) psym->st_shndx);
							sec_name = name_buf;
						}
					}
					print_symbol (22, sec_name);
				}
				else if (strtab == NULL)
					printf (("<string table index: %3ld>"), psym->st_name);
				else if (psym->st_name >= strtablen)
					printf (("<corrupt string table index: %3ld>"), psym->st_name);
				else
					print_symbol (22, strtab + psym->st_name);

				if (is_rela)
				{
					bfd_signed_vma off = rels[i].r_addend;

					if (off < 0)
						printf (" - %" BFD_VMA_FMT "x", - off);
					else
						printf (" + %" BFD_VMA_FMT "x", off);
				}
			}
		}
		else if (is_rela)
		{
			bfd_signed_vma off = rels[i].r_addend;

			printf ("%*c", is_32bit_elf ? 12 : 20, ' ');
			if (off < 0)
				printf ("-%" BFD_VMA_FMT "x", - off);
			else
				printf ("%" BFD_VMA_FMT "x", off);
		}

		putchar ('\n');
	}

	free (rels);
#endif
}

static char *
get_file_type (unsigned e_type)
{
	static char buff[32];

	switch (e_type)
	{
	case ET_NONE:
		return ("NONE (None)");
	case ET_REL:
		return ("REL (Relocatable file)");
	case ET_EXEC:
		return ("EXEC (Executable file)");
	case ET_DYN:
		return ("DYN (Shared object file)");
	case ET_CORE:
		return ("CORE (Core file)");

	default:
		if ((e_type >= ET_LOPROC) && (e_type <= ET_HIPROC))
			snprintf (buff, sizeof (buff), ("Processor Specific: (%x)"), e_type);
		else if ((e_type >= ET_LOOS) && (e_type <= ET_HIOS))
			snprintf (buff, sizeof (buff), ("OS Specific: (%x)"), e_type);
		else
			snprintf (buff, sizeof (buff), ("<unknown>: %x"), e_type);
		return buff;
	}
}


#if 0

static const char *
get_arm_segment_type (unsigned long type)
{
	switch (type)
	{
	case PT_ARM_EXIDX:
		return "EXIDX";
	default:
		break;
	}

	return NULL;
}


static const char *
get_segment_type (unsigned long p_type)
{
	static char buff[32];

	switch (p_type)
	{
	case PT_NULL:
		return "NULL";
	case PT_LOAD:
		return "LOAD";
	case PT_DYNAMIC:
		return "DYNAMIC";
	case PT_INTERP:
		return "INTERP";
	case PT_NOTE:
		return "NOTE";
	case PT_SHLIB:
		return "SHLIB";
	case PT_PHDR:
		return "PHDR";
	case PT_TLS:
		return "TLS";

	case PT_GNU_EH_FRAME:
		return "GNU_EH_FRAME";
	case PT_GNU_STACK:
		return "GNU_STACK";
	case PT_GNU_RELRO:
		return "GNU_RELRO";

	default:
		if ((p_type >= PT_LOPROC) && (p_type <= PT_HIPROC))
		{
			const char * result;

			switch (elf_header.e_machine)
			{
			case EM_ARM:
				result = get_arm_segment_type (p_type);
				break;
			default:
				result = NULL;
				break;
			}

			if (result != NULL)
				return result;

			sprintf (buff, "LOPROC+%lx", p_type - PT_LOPROC);
		}
		else if ((p_type >= PT_LOOS) && (p_type <= PT_HIOS))
		{
			const char * result;

			switch (elf_header.e_machine)
			{
			default:
				result = NULL;
				break;
			}

			if (result != NULL)
				return result;

			sprintf (buff, "LOOS+%lx", p_type - PT_LOOS);
		}
		else
			snprintf (buff, sizeof (buff), ("<unknown>: %lx"), p_type);

		return buff;
	}
}


#define OPTION_DEBUG_DUMP	512
#define OPTION_DYN_SYMS		513
#define OPTION_DWARF_DEPTH	514
#define OPTION_DWARF_START	515
#define OPTION_DWARF_CHECK	516

static struct option options[] =
{
	{"all",	       no_argument, 0, 'a'},
	{"file-header",      no_argument, 0, 'h'},
	{"program-headers",  no_argument, 0, 'l'},
	{"headers",	       no_argument, 0, 'e'},
	{"histogram",	       no_argument, 0, 'I'},
	{"segments",	       no_argument, 0, 'l'},
	{"sections",	       no_argument, 0, 'S'},
	{"section-headers",  no_argument, 0, 'S'},
	{"section-groups",   no_argument, 0, 'g'},
	{"section-details",  no_argument, 0, 't'},
	{"full-section-name",no_argument, 0, 'N'},
	{"symbols",	       no_argument, 0, 's'},
	{"syms",	       no_argument, 0, 's'},
	{"dyn-syms",	       no_argument, 0, OPTION_DYN_SYMS},
	{"relocs",	       no_argument, 0, 'r'},
	{"notes",	       no_argument, 0, 'n'},
	{"dynamic",	       no_argument, 0, 'd'},
	{"arch-specific",    no_argument, 0, 'A'},
	{"version-info",     no_argument, 0, 'V'},
	{"use-dynamic",      no_argument, 0, 'D'},
	{"unwind",	       no_argument, 0, 'u'},
	{"archive-index",    no_argument, 0, 'c'},
	{"hex-dump",	       required_argument, 0, 'x'},
	{"relocated-dump",   required_argument, 0, 'R'},
	{"string-dump",      required_argument, 0, 'p'},
#ifdef SUPPORT_DISASSEMBLY
	{"instruction-dump", required_argument, 0, 'i'},
#endif
	{"debug-dump",       optional_argument, 0, OPTION_DEBUG_DUMP},

	{"dwarf-depth",      required_argument, 0, OPTION_DWARF_DEPTH},
	{"dwarf-start",      required_argument, 0, OPTION_DWARF_START},
	{"dwarf-check",      no_argument, 0, OPTION_DWARF_CHECK},

	{"version",	       no_argument, 0, 'v'},
	{"wide",	       no_argument, 0, 'W'},
	{"help",	       no_argument, 0, 'H'},
	{0,		       no_argument, 0, 0}
};

/* Record the fact that the user wants the contents of section number
   SECTION to be displayed using the method(s) encoded as flags bits
   in TYPE.  Note, TYPE can be zero if we are creating the array for
   the first time.  */

static void
request_dump_bynumber (unsigned int section, dump_type type)
{
	if (section >= num_dump_sects)
	{
		dump_type * new_dump_sects;

		new_dump_sects = (dump_type *) calloc (section + 1,
											   sizeof (* dump_sects));

		if (new_dump_sects == NULL)
			printf (("Out of memory allocating dump request table.\n"));
		else
		{
			/* Copy current flag settings.  */
			memcpy (new_dump_sects, dump_sects, num_dump_sects * sizeof (* dump_sects));

			free (dump_sects);

			dump_sects = new_dump_sects;
			num_dump_sects = section + 1;
		}
	}

	if (dump_sects)
		dump_sects[section] |= type;

	return;
}

/* Request a dump by section name.  */

static void
request_dump_byname (const char * section, dump_type type)
{
	struct dump_list_entry * new_request;

	new_request = (struct dump_list_entry *)
				  malloc (sizeof (struct dump_list_entry));
	if (!new_request)
		printf (("Out of memory allocating dump request table.\n"));

	new_request->name = strdup (section);
	if (!new_request->name)
		printf (("Out of memory allocating dump request table.\n"));

	new_request->type = type;

	new_request->next = dump_sects_byname;
	dump_sects_byname = new_request;
}

static inline void
request_dump (dump_type type)
{
	int section;
	char * cp;

	do_dump++;
	section = strtoul (optarg, & cp, 0);

	if (! *cp && section >= 0)
		request_dump_bynumber (section, type);
	else
		request_dump_byname (optarg, type);
}

static void
parse_args (int argc, char ** argv)
{
	int c;

	if (argc < 2)
		usage (stderr);

	while ((c = getopt_long
				(argc, argv, "ADHINR:SVWacdeghi:lnp:rstuvw::x:", options, NULL)) != EOF)
	{
		switch (c)
		{
		case 0:
			/* Long options.  */
			break;
		case 'H':
			usage (stdout);
			break;

		case 'a':
			do_syms++;
			do_reloc++;
			do_unwind++;
			do_dynamic++;
			do_header++;
			do_sections++;
			do_section_groups++;
			do_segments++;
			do_version++;
			do_histogram++;
			do_arch++;
			do_notes++;
			break;
		case 'g':
			do_section_groups++;
			break;
		case 't':
		case 'N':
			do_sections++;
			do_section_details++;
			break;
		case 'e':
			do_header++;
			do_sections++;
			do_segments++;
			break;
		case 'A':
			do_arch++;
			break;
		case 'D':
			do_using_dynamic++;
			break;
		case 'r':
			do_reloc++;
			break;
		case 'u':
			do_unwind++;
			break;
		case 'h':
			do_header++;
			break;
		case 'l':
			do_segments++;
			break;
		case 's':
			do_syms++;
			break;
		case 'S':
			do_sections++;
			break;
		case 'd':
			do_dynamic++;
			break;
		case 'I':
			do_histogram++;
			break;
		case 'n':
			do_notes++;
			break;
		case 'c':
			do_archive_index++;
			break;
		case 'x':
			request_dump (HEX_DUMP);
			break;
		case 'p':
			request_dump (STRING_DUMP);
			break;
		case 'R':
			request_dump (RELOC_DUMP);
			break;
		case 'w':
			do_dump++;
			if (optarg == 0)
			{
				do_debugging = 1;
				dwarf_select_sections_all ();
			}
			else
			{
				do_debugging = 0;
				dwarf_select_sections_by_letters (optarg);
			}
			break;
		case OPTION_DEBUG_DUMP:
			do_dump++;
			if (optarg == 0)
				do_debugging = 1;
			else
			{
				do_debugging = 0;
				dwarf_select_sections_by_names (optarg);
			}
			break;
		case OPTION_DWARF_DEPTH:
		{
			char *cp;

			dwarf_cutoff_level = strtoul (optarg, & cp, 0);
		}
		break;
		case OPTION_DWARF_START:
		{
			char *cp;

			dwarf_start_die = strtoul (optarg, & cp, 0);
		}
		break;
		case OPTION_DWARF_CHECK:
			dwarf_check = 1;
			break;
		case OPTION_DYN_SYMS:
			do_dyn_syms++;
			break;
#ifdef SUPPORT_DISASSEMBLY
		case 'i':
			request_dump (DISASS_DUMP);
			break;
#endif
		case 'v':
			print_version (program_name);
			break;
		case 'V':
			do_version++;
			break;
		case 'W':
			1++;
			break;
		default:
			/* xgettext:c-format */
			printf (("Invalid option '-%c'\n"), c);
			/* Drop through.  */
		case '?':
			usage (stderr);
		}
	}

	if (!do_dynamic && !do_syms && !do_reloc && !do_unwind && !do_sections
			&& !do_segments && !do_header && !do_dump && !do_version
			&& !do_histogram && !do_debugging && !do_arch && !do_notes
			&& !do_section_groups && !do_archive_index
			&& !do_dyn_syms)
		usage (stderr);
	else if (argc < 3)
	{
		warn (("Nothing to do.\n"));
		usage (stderr);
	}
}

#endif
static const char *
get_elf_class (unsigned int elf_class)
{
	static char buff[32];

	switch (elf_class)
	{
	case ELFCLASSNONE:
		return ("none");
	case ELFCLASS32:
		return "ELF32";
	case ELFCLASS64:
		return "ELF64";
	default:
		snprintf (buff, sizeof (buff), ("<unknown: %x>"), elf_class);
		return buff;
	}
}

static const char *
get_data_encoding (unsigned int encoding)
{
	static char buff[32];

	switch (encoding)
	{
	case ELFDATANONE:
		return ("none");
	case ELFDATA2LSB:
		return ("2's complement, little endian");
	case ELFDATA2MSB:
		return ("2's complement, big endian");
	default:
		snprintf (buff, sizeof (buff), ("<unknown: %x>"), encoding);
		return buff;
	}
}


/* Decode the data held in 'elf_header'.  */

static int
process_file_header (void)
{
	if (   elf_header.e_ident[EI_MAG0] != ELFMAG0
			|| elf_header.e_ident[EI_MAG1] != ELFMAG1
			|| elf_header.e_ident[EI_MAG2] != ELFMAG2
			|| elf_header.e_ident[EI_MAG3] != ELFMAG3)
	{
		printf("Not an ELF file - it has the wrong magic bytes at the start\n");
		return 0;
	}

	if (section_headers != NULL)
	{
		if (elf_header.e_phnum == PN_XNUM
				&& section_headers[0].sh_info != 0)
			elf_header.e_phnum = section_headers[0].sh_info;
		if (elf_header.e_shnum == SHN_UNDEF)
			elf_header.e_shnum = section_headers[0].sh_size;
		if (elf_header.e_shstrndx == (SHN_XINDEX & 0xffff))
			elf_header.e_shstrndx = section_headers[0].sh_link;
		else if (elf_header.e_shstrndx >= elf_header.e_shnum)
			elf_header.e_shstrndx = SHN_UNDEF;
		free (section_headers);
		section_headers = NULL;
	}

	printf("Header processed! \n ");

	return 1;
}

static int
get_program_headers (FILE * file, Elf_Internal_Phdr * pheaders)
{
	Elf_External_Phdr * phdrs;
	Elf_External_Phdr * external;
	Elf_Internal_Phdr *   internal;
	unsigned int i;

	phdrs = (Elf_External_Phdr *) get_data (NULL, file, elf_header.e_phoff,
			elf_header.e_phentsize,
			elf_header.e_phnum,
			("program headers"));
	if (!phdrs)
		return 0;

	for (i = 0, internal = pheaders, external = phdrs;
			i < elf_header.e_phnum;
			i++, internal++, external++)
	{
		internal->p_type   = BYTE_GET (external->p_type);
		internal->p_offset = BYTE_GET (external->p_offset);
		internal->p_vaddr  = BYTE_GET (external->p_vaddr);
		internal->p_paddr  = BYTE_GET (external->p_paddr);
		internal->p_filesz = BYTE_GET (external->p_filesz);
		internal->p_memsz  = BYTE_GET (external->p_memsz);
		internal->p_flags  = BYTE_GET (external->p_flags);
		internal->p_align  = BYTE_GET (external->p_align);
	}

	free (phdrs);

	return 1;
}

/* Returns 1 if the program headers were read into `program_headers'.  */

static int
get_program_headers (FILE * file)
{
	Elf_Internal_Phdr * phdrs;

	/* Check cache of prior read.  */
	if (program_headers != NULL)
		return 1;

	phdrs = (Elf_Internal_Phdr *) cmalloc (elf_header.e_phnum,
										   sizeof (Elf_Internal_Phdr));

	if (phdrs == NULL)
	{
		printf (("Out of memory\n"));
		return 0;
	}

	if (get_program_headers (file, phdrs))
	{
		program_headers = phdrs;
		return 1;
	}

	free (phdrs);
	return 0;
}


/* Returns 1 if the program headers were loaded.  */

static int
process_program_headers (FILE * file)
{
	Elf_Internal_Phdr * segment;
	unsigned int i;
	if (elf_header.e_phnum == 0)
	{
		/* PR binutils/12467.  */
		if (elf_header.e_phoff != 0)
			printf ("possibly corrupt ELF header - it has a non-zero program"
					" header offset, but no program headers");
		else if (do_segments)
			printf ("\nThere are no program headers in this file.\n");
		return 0;
	}

	if (! get_program_headers (file))
		return 0;

#if 0

	dynamic_addr = 0;
	dynamic_size = 0;

	for (i = 0, segment = program_headers;
			i < elf_header.e_phnum;
			i++, segment++)
	{
		if (do_segments)
		{
			printf ("  %-14.14s ", get_segment_type (segment->p_type));

			if (is_32bit_elf)
			{
				printf ("0x%6.6lx ", (unsigned long) segment->p_offset);
				printf ("0x%8.8lx ", (unsigned long) segment->p_vaddr);
				printf ("0x%8.8lx ", (unsigned long) segment->p_paddr);
				printf ("0x%5.5lx ", (unsigned long) segment->p_filesz);
				printf ("0x%5.5lx ", (unsigned long) segment->p_memsz);
				printf ("%c%c%c ",
						(segment->p_flags & PF_R ? 'R' : ' '),
						(segment->p_flags & PF_W ? 'W' : ' '),
						(segment->p_flags & PF_X ? 'E' : ' '));
				printf ("%#lx", (unsigned long) segment->p_align);
			}
			else if (1)
			{
				if ((unsigned long) segment->p_offset == segment->p_offset)
					printf ("0x%6.6lx ", (unsigned long) segment->p_offset);
				else
				{
					print_vma (segment->p_offset, FULL_HEX);
					putchar (' ');
				}

				print_vma (segment->p_vaddr, FULL_HEX);
				putchar (' ');
				print_vma (segment->p_paddr, FULL_HEX);
				putchar (' ');

				if ((unsigned long) segment->p_filesz == segment->p_filesz)
					printf ("0x%6.6lx ", (unsigned long) segment->p_filesz);
				else
				{
					print_vma (segment->p_filesz, FULL_HEX);
					putchar (' ');
				}

				if ((unsigned long) segment->p_memsz == segment->p_memsz)
					printf ("0x%6.6lx", (unsigned long) segment->p_memsz);
				else
				{
					print_vma (segment->p_memsz, FULL_HEX);
				}

				printf (" %c%c%c ",
						(segment->p_flags & PF_R ? 'R' : ' '),
						(segment->p_flags & PF_W ? 'W' : ' '),
						(segment->p_flags & PF_X ? 'E' : ' '));

				if ((unsigned long) segment->p_align == segment->p_align)
					printf ("%#lx", (unsigned long) segment->p_align);
				else
				{
					print_vma (segment->p_align, PREFIX_HEX);
				}
			}
			else
			{
				print_vma (segment->p_offset, FULL_HEX);
				putchar (' ');
				print_vma (segment->p_vaddr, FULL_HEX);
				putchar (' ');
				print_vma (segment->p_paddr, FULL_HEX);
				printf ("\n                 ");
				print_vma (segment->p_filesz, FULL_HEX);
				putchar (' ');
				print_vma (segment->p_memsz, FULL_HEX);
				printf ("  %c%c%c    ",
						(segment->p_flags & PF_R ? 'R' : ' '),
						(segment->p_flags & PF_W ? 'W' : ' '),
						(segment->p_flags & PF_X ? 'E' : ' '));
				print_vma (segment->p_align, HEX);
			}
		}

		switch (segment->p_type)
		{
		case PT_DYNAMIC:
			if (dynamic_addr)
				printf (("more than one dynamic segment\n"));

			/* By default, assume that the .dynamic section is the first
			   section in the DYNAMIC segment.  */
			dynamic_addr = segment->p_offset;
			dynamic_size = segment->p_filesz;

			/* Try to locate the .dynamic section. If there is
			   a section header table, we can easily locate it.  */
			if (section_headers != NULL)
			{
				Elf_Internal_Shdr * sec;

				sec = find_section (".dynamic");
				if (sec == NULL || sec->sh_size == 0)
				{
					/* A corresponding .dynamic section is expected, but on
					   IA-64/OpenVMS it is OK for it to be missing.  */
					if (!is_ia64_vms ())
						printf (("no .dynamic section in the dynamic segment\n"));
					break;
				}

				if (sec->sh_type == SHT_NOBITS)
				{
					dynamic_size = 0;
					break;
				}

				dynamic_addr = sec->sh_offset;
				dynamic_size = sec->sh_size;

				if (dynamic_addr < segment->p_offset
						|| dynamic_addr > segment->p_offset + segment->p_filesz)
					warn (("the .dynamic section is not contained"
							" within the dynamic segment\n"));
				else if (dynamic_addr > segment->p_offset)
					warn (("the .dynamic section is not the first section"
							" in the dynamic segment.\n"));
			}
			break;
		}
	}

#endif
	return 1;
}
//#if 0

/* Find the file offset corresponding to VMA by using the program headers.  */

static long
offset_from_vma (FILE * file, bfd_vma vma, bfd_size_type size)
{
	Elf_Internal_Phdr * seg;

	if (! get_program_headers (file))
	{
		//warn ("Cannot interpret virtual addresses without program headers.\n");
		return (long) vma;
	}

	for (seg = program_headers;
			seg < program_headers + elf_header.e_phnum;
			++seg)
	{
		if (seg->p_type != PT_LOAD)
			continue;

		if (vma >= (seg->p_vaddr & -seg->p_align)
				&& vma + size <= seg->p_vaddr + seg->p_filesz)
			return vma - seg->p_vaddr + seg->p_offset;
	}

	//warn (("Virtual address 0x%lx not located in any PT_LOAD segment.\n"),
	//	  (unsigned long) vma);
	return (long) vma;
}

//#endif

static int
get_section_headers (FILE * file, unsigned int num)
{
	Elf_External_Shdr * shdrs;
	Elf_Internal_Shdr *   internal;
	unsigned int i;

	shdrs = (Elf_External_Shdr *) get_data (NULL, file, elf_header.e_shoff,
			elf_header.e_shentsize, num,
			("section headers"));
	if (!shdrs)
		return 0;

	section_headers = (Elf_Internal_Shdr *) cmalloc (num,
					  sizeof (Elf_Internal_Shdr));

	if (section_headers == NULL)
	{
		printf ("Out of memory\n");
		return 0;
	}

	for (i = 0, internal = section_headers;
			i < num;
			i++, internal++)
	{
		internal->sh_name      = BYTE_GET (shdrs[i].sh_name);
		internal->sh_type      = BYTE_GET (shdrs[i].sh_type);
		internal->sh_flags     = BYTE_GET (shdrs[i].sh_flags);
		internal->sh_addr      = BYTE_GET (shdrs[i].sh_addr);
		internal->sh_offset    = BYTE_GET (shdrs[i].sh_offset);
		internal->sh_size      = BYTE_GET (shdrs[i].sh_size);
		internal->sh_link      = BYTE_GET (shdrs[i].sh_link);
		internal->sh_info      = BYTE_GET (shdrs[i].sh_info);
		internal->sh_addralign = BYTE_GET (shdrs[i].sh_addralign);
		internal->sh_entsize   = BYTE_GET (shdrs[i].sh_entsize);
	}

	free (shdrs);

	return 1;
}

static Elf_Internal_Sym *
get_elf_symbols (FILE * file,
					   Elf_Internal_Shdr * section,
					   unsigned long * num_syms_return)
{
	unsigned long number = 0;
	Elf_External_Sym * esyms = NULL;
	Elf_External_Sym_Shndx * shndx = NULL;
	Elf_Internal_Sym * isyms = NULL;
	Elf_Internal_Sym * psym;
	unsigned int j;

	/* Run some sanity checks first.  */
	if (section->sh_entsize == 0)
	{
		printf (("sh_entsize is zero\n"));
		goto exit_point;
	}

	number = section->sh_size / section->sh_entsize;

	if (number * sizeof (Elf_External_Sym) > section->sh_size + 1)
	{
		printf (("Invalid sh_entsize\n"));
		goto exit_point;
	}

	esyms = (Elf_External_Sym *) get_data (NULL, file, section->sh_offset, 1,
			section->sh_size, ("symbols"));
	if (esyms == NULL)
		goto exit_point;

	shndx = NULL;
	if (symtab_shndx_hdr != NULL
			&& (symtab_shndx_hdr->sh_link
				== (unsigned long) (section - section_headers)))
	{
		shndx = (Elf_External_Sym_Shndx *) get_data (NULL, file,
				symtab_shndx_hdr->sh_offset,
				1, symtab_shndx_hdr->sh_size,
				("symbol table section indicies"));
		if (shndx == NULL)
			goto exit_point;
	}

	isyms = (Elf_Internal_Sym *) cmalloc (number, sizeof (Elf_Internal_Sym));

	if (isyms == NULL)
	{
		printf (("Out of memory\n"));
		goto exit_point;
	}

	for (j = 0, psym = isyms; j < number; j++, psym++)
	{
		psym->st_name  = BYTE_GET (esyms[j].st_name);
		psym->st_value = BYTE_GET (esyms[j].st_value);
		psym->st_size  = BYTE_GET (esyms[j].st_size);
		psym->st_shndx = BYTE_GET (esyms[j].st_shndx);
		if (psym->st_shndx == (SHN_XINDEX & 0xffff) && shndx != NULL)
			psym->st_shndx
				= byte_get ((unsigned char *) &shndx[j], sizeof (shndx[j]));
		else if (psym->st_shndx >= (SHN_LORESERVE & 0xffff))
			psym->st_shndx += SHN_LORESERVE - (SHN_LORESERVE & 0xffff);
		psym->st_info  = BYTE_GET (esyms[j].st_info);
		psym->st_other = BYTE_GET (esyms[j].st_other);
	}

exit_point:
	if (shndx != NULL)
		free (shndx);
	if (esyms != NULL)
		free (esyms);

	if (num_syms_return != NULL)
		* num_syms_return = isyms == NULL ? 0 : number;

	return isyms;
}

#if 0
static const char *
get_elf_section_flags (bfd_vma sh_flags)
{
	static char buff[1024];
	char * p = buff;
	int field_size = is_32bit_elf ? 8 : 16;
	int sindex;
	int size = sizeof (buff) - (field_size + 4 + 1);
	bfd_vma os_flags = 0;
	bfd_vma proc_flags = 0;
	bfd_vma unknown_flags = 0;
	static const struct
	{
		const char * str;
		int len;
	}
	flags [] =
	{
		/*  0 */ { STRING_COMMA_LEN ("WRITE") },
		/*  1 */ { STRING_COMMA_LEN ("ALLOC") },
		/*  2 */ { STRING_COMMA_LEN ("EXEC") },
		/*  3 */ { STRING_COMMA_LEN ("MERGE") },
		/*  4 */ { STRING_COMMA_LEN ("STRINGS") },
		/*  5 */ { STRING_COMMA_LEN ("INFO LINK") },
		/*  6 */ { STRING_COMMA_LEN ("LINK ORDER") },
		/*  7 */ { STRING_COMMA_LEN ("OS NONCONF") },
		/*  8 */ { STRING_COMMA_LEN ("GROUP") },
		/*  9 */ { STRING_COMMA_LEN ("TLS") },
		/* IA-64 specific.  */
		/* 10 */ { STRING_COMMA_LEN ("SHORT") },
		/* 11 */ { STRING_COMMA_LEN ("NORECOV") },
		/* IA-64 OpenVMS specific.  */
		/* 12 */ { STRING_COMMA_LEN ("VMS_GLOBAL") },
		/* 13 */ { STRING_COMMA_LEN ("VMS_OVERLAID") },
		/* 14 */ { STRING_COMMA_LEN ("VMS_SHARED") },
		/* 15 */ { STRING_COMMA_LEN ("VMS_VECTOR") },
		/* 16 */ { STRING_COMMA_LEN ("VMS_ALLOC_64BIT") },
		/* 17 */ { STRING_COMMA_LEN ("VMS_PROTECTED") },
		/* Generic.  */
		/* 18 */ { STRING_COMMA_LEN ("EXCLUDE") },
		/* SPARC specific.  */
		/* 19 */ { STRING_COMMA_LEN ("ORDERED") }
	};

	if (do_section_details)
	{
		sprintf (buff, "[%*.*lx]: ",
				 field_size, field_size, (unsigned long) sh_flags);
		p += field_size + 4;
	}

	while (sh_flags)
	{
		bfd_vma flag;

		flag = sh_flags & - sh_flags;
		sh_flags &= ~ flag;

		if (do_section_details)
		{
			switch (flag)
			{
			case SHF_WRITE:
				sindex = 0;
				break;
			case SHF_ALLOC:
				sindex = 1;
				break;
			case SHF_EXECINSTR:
				sindex = 2;
				break;
			case SHF_MERGE:
				sindex = 3;
				break;
			case SHF_STRINGS:
				sindex = 4;
				break;
			case SHF_INFO_LINK:
				sindex = 5;
				break;
			case SHF_LINK_ORDER:
				sindex = 6;
				break;
			case SHF_OS_NONCONFORMING:
				sindex = 7;
				break;
			case SHF_GROUP:
				sindex = 8;
				break;
			case SHF_TLS:
				sindex = 9;
				break;
			case SHF_EXCLUDE:
				sindex = 18;
				break;

			default:
				sindex = -1;
				switch (elf_header.e_machine)
				{
				case EM_IA_64:
					if (flag == SHF_IA_64_SHORT)
						sindex = 10;
					else if (flag == SHF_IA_64_NORECOV)
						sindex = 11;
#ifdef BFD64
					else if (elf_header.e_ident[EI_OSABI] == ELFOSABI_OPENVMS)
						switch (flag)
						{
						case SHF_IA_64_VMS_GLOBAL:
							sindex = 12;
							break;
						case SHF_IA_64_VMS_OVERLAID:
							sindex = 13;
							break;
						case SHF_IA_64_VMS_SHARED:
							sindex = 14;
							break;
						case SHF_IA_64_VMS_VECTOR:
							sindex = 15;
							break;
						case SHF_IA_64_VMS_ALLOC_64BIT:
							sindex = 16;
							break;
						case SHF_IA_64_VMS_PROTECTED:
							sindex = 17;
							break;
						default:
							break;
						}
#endif
					break;

				case EM_386:
				case EM_486:
				case EM_X86_64:
				case EM_L1OM:
				case EM_K1OM:
				case EM_OLD_SPARCV9:
				case EM_SPARC32PLUS:
				case EM_SPARCV9:
				case EM_SPARC:
					if (flag == SHF_ORDERED)
						sindex = 19;
					break;
				default:
					break;
				}
			}

			if (sindex != -1)
			{
				if (p != buff + field_size + 4)
				{
					if (size < (10 + 2))
						abort ();
					size -= 2;
					*p++ = ',';
					*p++ = ' ';
				}

				size -= flags [sindex].len;
				p = stpcpy (p, flags [sindex].str);
			}
			else if (flag & SHF_MASKOS)
				os_flags |= flag;
			else if (flag & SHF_MASKPROC)
				proc_flags |= flag;
			else
				unknown_flags |= flag;
		}
		else
		{
			switch (flag)
			{
			case SHF_WRITE:
				*p = 'W';
				break;
			case SHF_ALLOC:
				*p = 'A';
				break;
			case SHF_EXECINSTR:
				*p = 'X';
				break;
			case SHF_MERGE:
				*p = 'M';
				break;
			case SHF_STRINGS:
				*p = 'S';
				break;
			case SHF_INFO_LINK:
				*p = 'I';
				break;
			case SHF_LINK_ORDER:
				*p = 'L';
				break;
			case SHF_OS_NONCONFORMING:
				*p = 'O';
				break;
			case SHF_GROUP:
				*p = 'G';
				break;
			case SHF_TLS:
				*p = 'T';
				break;
			case SHF_EXCLUDE:
				*p = 'E';
				break;

			default:
				if ((elf_header.e_machine == EM_X86_64
						|| elf_header.e_machine == EM_L1OM
						|| elf_header.e_machine == EM_K1OM)
						&& flag == SHF_X86_64_LARGE)
					*p = 'l';
				else if (flag & SHF_MASKOS)
				{
					*p = 'o';
					sh_flags &= ~ SHF_MASKOS;
				}
				else if (flag & SHF_MASKPROC)
				{
					*p = 'p';
					sh_flags &= ~ SHF_MASKPROC;
				}
				else
					*p = 'x';
				break;
			}
			p++;
		}
	}

	if (do_section_details)
	{
		if (os_flags)
		{
			size -= 5 + field_size;
			if (p != buff + field_size + 4)
			{
				if (size < (2 + 1))
					abort ();
				size -= 2;
				*p++ = ',';
				*p++ = ' ';
			}
			sprintf (p, "OS (%*.*lx)", field_size, field_size,
					 (unsigned long) os_flags);
			p += 5 + field_size;
		}
		if (proc_flags)
		{
			size -= 7 + field_size;
			if (p != buff + field_size + 4)
			{
				if (size < (2 + 1))
					abort ();
				size -= 2;
				*p++ = ',';
				*p++ = ' ';
			}
			sprintf (p, "PROC (%*.*lx)", field_size, field_size,
					 (unsigned long) proc_flags);
			p += 7 + field_size;
		}
		if (unknown_flags)
		{
			size -= 10 + field_size;
			if (p != buff + field_size + 4)
			{
				if (size < (2 + 1))
					abort ();
				size -= 2;
				*p++ = ',';
				*p++ = ' ';
			}
			sprintf (p, ("UNKNOWN (%*.*lx)"), field_size, field_size,
					 (unsigned long) unknown_flags);
			p += 10 + field_size;
		}
	}

	*p = '\0';
	return buff;
}
#endif

static int
process_section_headers (FILE * file)
{
	Elf_Internal_Shdr * section;
	unsigned int i;
	int eh_addr_size;

	section_headers = NULL;

	if (elf_header.e_shnum == 0)
	{
		/* PR binutils/12467.  */
		if (elf_header.e_shoff != 0)
			printf ("possibly corrupt ELF file header - it has a non-zero"
					" section header offset, but no section headers\n");

		return 1;
	}


	if (! get_section_headers (file, elf_header.e_shnum))
		return 0;

	/* Read in the string table, so that we have names to display.  */
	if (elf_header.e_shstrndx != SHN_UNDEF
			&& elf_header.e_shstrndx < elf_header.e_shnum)
	{
		section = section_headers + elf_header.e_shstrndx;

		if (section->sh_size != 0)
		{
			string_table = (char *) get_data (NULL, file, section->sh_offset,
											  1, section->sh_size,
											  ("string table"));

			string_table_length = string_table != NULL ? section->sh_size : 0;
		}
	}

	/* Scan the sections for the dynamic symbol table
	   and dynamic string table and debug sections.  */
	dynamic_symbols = NULL;
	dynamic_strings = NULL;
	dynamic_syminfo = NULL;
	symtab_shndx_hdr = NULL;

	eh_addr_size = is_32bit_elf ? 4 : 8;

#define CHECK_ENTSIZE_VALUES(section, i, size32, size64) \
  do									    \
    {									    \
      size_t expected_entsize						    \
	= is_32bit_elf ? size32 : size64;				    \
      if (section->sh_entsize != expected_entsize)			    \
	printf (("Section %d has invalid sh_entsize %lx (expected %lx)\n"), \
	       i, (unsigned long int) section->sh_entsize,		    \
	       (unsigned long int) expected_entsize);			    \
      section->sh_entsize = expected_entsize;				    \
    }									    \
  while (0)
#define CHECK_ENTSIZE(section, i, type) \
  CHECK_ENTSIZE_VALUES (section, i, sizeof (Elf32_External_##type),	    \
			sizeof (Elf64_External_##type))

	for (i = 0, section = section_headers;
			i < elf_header.e_shnum;
			i++, section++)
	{
		char * name = "<none"; //	SECTION_NAME (section);		// TODO: NEED FIX THIS!

		if (section->sh_type == SHT_DYNSYM)
		{
			if (dynamic_symbols != NULL)
			{
				printf (("File contains multiple dynamic symbol tables\n"));
				continue;
			}

			CHECK_ENTSIZE (section, i, Sym);
			dynamic_symbols = get_elf_symbols (file, section, & num_dynamic_syms);
		}
		else if (section->sh_type == SHT_STRTAB
				 && strcmp (name, ".dynstr"))
		{
			if (dynamic_strings != NULL)
			{
				printf (("File contains multiple dynamic string tables\n"));
				continue;
			}

			dynamic_strings = (char *) get_data (NULL, file, section->sh_offset,
												 1, section->sh_size,
												 ("dynamic strings"));
			dynamic_strings_length = dynamic_strings == NULL ? 0 : section->sh_size;
		}
		else if (section->sh_type == SHT_SYMTAB_SHNDX)
		{
			if (symtab_shndx_hdr != NULL)
			{
				printf (("File contains multiple symtab shndx tables\n"));
				continue;
			}
			symtab_shndx_hdr = section;
		}
		else if (section->sh_type == SHT_SYMTAB)
			CHECK_ENTSIZE (section, i, Sym);
		else if (section->sh_type == SHT_GROUP)
			CHECK_ENTSIZE_VALUES (section, i, GRP_ENTRY_SIZE, GRP_ENTRY_SIZE);
		else if (section->sh_type == SHT_REL)
			CHECK_ENTSIZE (section, i, Rel);
		else if (section->sh_type == SHT_RELA)
			CHECK_ENTSIZE (section, i, Rela);

	}

	return 1;
}


static struct
{
	const char * name;
	int reloc;
	int size;
	int rela;
} dynamic_relocations [] =
{
	{ "REL", DT_REL, DT_RELSZ, FALSE },
	{ "RELA", DT_RELA, DT_RELASZ, TRUE },
	{ "PLT", DT_JMPREL, DT_PLTRELSZ, UNKNOWN }
};

/* Process the reloc section.  */

static int
process_relocs (FILE * file)
{
	unsigned long rel_size;
	unsigned long rel_offset;

	if (do_using_dynamic)
	{
		int is_rela;
		const char * name;
		int has_dynamic_reloc;
		unsigned int i;

		has_dynamic_reloc = 0;

		for (i = 0; i < ARRAY_SIZE (dynamic_relocations); i++)
		{
			is_rela = dynamic_relocations [i].rela;
			name = dynamic_relocations [i].name;
			rel_size = dynamic_info [dynamic_relocations [i].size];
			rel_offset = dynamic_info [dynamic_relocations [i].reloc];

			has_dynamic_reloc |= rel_size;

			if (is_rela == UNKNOWN)
			{
				if (dynamic_relocations [i].reloc == DT_JMPREL)
					switch (dynamic_info[DT_PLTREL])
					{
					case DT_REL:
						is_rela = FALSE;
						break;
					case DT_RELA:
						is_rela = TRUE;
						break;
					}
			}

			if (rel_size)
			{
				printf
				(("\n'%s' relocation section at offset 0x%lx contains %ld bytes:\n"),
				 name, rel_offset, rel_size);


				dump_relocations (file,
								  offset_from_vma (file, rel_offset, rel_size),
								  rel_size,
								  dynamic_symbols, num_dynamic_syms,
								  dynamic_strings, dynamic_strings_length, is_rela);

			}
		}

		if (! has_dynamic_reloc)
			printf (("\nThere are no dynamic relocations in this file.\n"));
	}
	else
	{
		Elf_Internal_Shdr * section;
		unsigned long i;
		int found = 0;

		for (i = 0, section = section_headers;
				i < elf_header.e_shnum;
				i++, section++)
		{
			if (   section->sh_type != SHT_RELA
					&& section->sh_type != SHT_REL)
				continue;

			rel_offset = section->sh_offset;
			rel_size   = section->sh_size;

			if (rel_size)
			{
				Elf_Internal_Shdr * strsec;
				int is_rela;

				printf (("\nRelocation section "));

				if (string_table == NULL)
					printf ("%d", section->sh_name);
				else
					printf ("'%s'", SECTION_NAME (section));

				printf ((" at offset 0x%lx contains %lu entries:\n"),
						rel_offset, (unsigned long) (rel_size / section->sh_entsize));

				is_rela = section->sh_type == SHT_RELA;

				if (section->sh_link != 0
						&& section->sh_link < elf_header.e_shnum)
				{
					Elf_Internal_Shdr * symsec;
					Elf_Internal_Sym *  symtab;
					unsigned long nsyms;
					unsigned long strtablen = 0;
					char * strtab = NULL;

					symsec = section_headers + section->sh_link;
					if (symsec->sh_type != SHT_SYMTAB
							&& symsec->sh_type != SHT_DYNSYM)
						continue;

					symtab = get_elf_symbols (file, symsec, & nsyms);

					if (symtab == NULL)
						continue;

					if (symsec->sh_link != 0
							&& symsec->sh_link < elf_header.e_shnum)
					{
						strsec = section_headers + symsec->sh_link;

						strtab = (char *) get_data (NULL, file, strsec->sh_offset,
													1, strsec->sh_size,
													("string table"));
						strtablen = strtab == NULL ? 0 : strsec->sh_size;
					}

					dump_relocations (file, rel_offset, rel_size,
									  symtab, nsyms, strtab, strtablen, is_rela);
					if (strtab)
						free (strtab);
					free (symtab);
				}
				else
					dump_relocations (file, rel_offset, rel_size,
									  NULL, 0, NULL, 0, is_rela);

				found = 1;
			}
		}

		if (! found)
			printf (("\nThere are no relocations in this file.\n"));
	}

	return 1;
}
#if 0
/* Process the unwind section.  */

/* An absolute address consists of a section and an offset.  If the
   section is NULL, the offset itself is the address, otherwise, the
   address equals to LOAD_ADDRESS(section) + offset.  */

struct absaddr
{
	unsigned short section;
	bfd_vma offset;
};

#define ABSADDR(a) \
  ((a).section \
   ? section_headers [(a).section].sh_addr + (a).offset \
   : (a).offset)

static void
find_symbol_for_address (Elf_Internal_Sym * symtab,
						 unsigned long nsyms,
						 const char * strtab,
						 unsigned long strtab_size,
						 struct absaddr addr,
						 const char ** symname,
						 bfd_vma * offset)
{
	bfd_vma dist = 0x100000;
	Elf_Internal_Sym * sym;
	Elf_Internal_Sym * best = NULL;
	unsigned long i;

	REMOVE_ARCH_BITS (addr.offset);

	for (i = 0, sym = symtab; i < nsyms; ++i, ++sym)
	{
		bfd_vma value = sym->st_value;

		REMOVE_ARCH_BITS (value);

		if (ELF_ST_TYPE (sym->st_info) == STT_FUNC
				&& sym->st_name != 0
				&& (addr.section == SHN_UNDEF || addr.section == sym->st_shndx)
				&& addr.offset >= value
				&& addr.offset - value < dist)
		{
			best = sym;
			dist = addr.offset - value;
			if (!dist)
				break;
		}
	}

	if (best)
	{
		*symname = (best->st_name >= strtab_size
					? ("<corrupt>") : strtab + best->st_name);
		*offset = dist;
		return;
	}

	*symname = NULL;
	*offset = addr.offset;
}

struct arm_section
{
	unsigned char *      data;		/* The unwind data.  */
	Elf_Internal_Shdr *  sec;		/* The cached unwind section header.  */
	Elf_Internal_Rela *  rela;		/* The cached relocations for this section.  */
	unsigned long        nrelas;		/* The number of relocations.  */
	unsigned int         rel_type;	/* REL or RELA ?  */
	Elf_Internal_Rela *  next_rela;	/* Cyclic pointer to the next reloc to process.  */
};

struct arm_unw_aux_info
{
	FILE *              file;		/* The file containing the unwind sections.  */
	Elf_Internal_Sym *  symtab;		/* The file's symbol table.  */
	unsigned long       nsyms;		/* Number of symbols.  */
	char *              strtab;		/* The file's string table.  */
	unsigned long       strtab_size;	/* Size of string table.  */
};

static const char *
arm_print_vma_and_name (struct arm_unw_aux_info *aux,
						bfd_vma fn, struct absaddr addr)
{
	const char *procname;
	bfd_vma sym_offset;

	if (addr.section == SHN_UNDEF)
		addr.offset = fn;

	find_symbol_for_address (aux->symtab, aux->nsyms, aux->strtab,
							 aux->strtab_size, addr, &procname,
							 &sym_offset);

	print_vma (fn, PREFIX_HEX);

	if (procname)
	{
		fputs (" <", stdout);
		fputs (procname, stdout);

		if (sym_offset)
			printf ("+0x%lx", (unsigned long) sym_offset);
		fputc ('>', stdout);
	}

	return procname;
}

static void
arm_free_section (struct arm_section *arm_sec)
{
	if (arm_sec->data != NULL)
		free (arm_sec->data);

	if (arm_sec->rela != NULL)
		free (arm_sec->rela);
}

/* 1) If SEC does not match the one cached in ARM_SEC, then free the current
      cached section and install SEC instead.
   2) Locate the 32-bit word at WORD_OFFSET in unwind section SEC
      and return its valued in * WORDP, relocating if necessary.
   3) Update the NEXT_RELA field in ARM_SEC and store the section index and
      relocation's offset in ADDR.
   4) If SYM_NAME is non-NULL and a relocation was applied, record the offset
      into the string table of the symbol associated with the reloc.  If no
      reloc was applied store -1 there.
   5) Return TRUE upon success, FALSE otherwise.  */

static bfd_boolean
get_unwind_section_word (struct arm_unw_aux_info *  aux,
						 struct arm_section *       arm_sec,
						 Elf_Internal_Shdr *        sec,
						 bfd_vma 		    word_offset,
						 unsigned int *             wordp,
						 struct absaddr *           addr,
						 bfd_vma *		    sym_name)
{
	Elf_Internal_Rela *rp;
	Elf_Internal_Sym *sym;
	const char * relname;
	unsigned int word;
	bfd_boolean wrapped;

	addr->section = SHN_UNDEF;
	addr->offset = 0;

	if (sym_name != NULL)
		*sym_name = (bfd_vma) -1;

	/* If necessary, update the section cache.  */
	if (sec != arm_sec->sec)
	{
		Elf_Internal_Shdr *relsec;

		arm_free_section (arm_sec);

		arm_sec->sec = sec;
		arm_sec->data = get_data (NULL, aux->file, sec->sh_offset, 1,
								  sec->sh_size, ("unwind data"));
		arm_sec->rela = NULL;
		arm_sec->nrelas = 0;

		for (relsec = section_headers;
				relsec < section_headers + elf_header.e_shnum;
				++relsec)
		{
			if (relsec->sh_info >= elf_header.e_shnum
					|| section_headers + relsec->sh_info != sec)
				continue;

			arm_sec->rel_type = relsec->sh_type;
			if (relsec->sh_type == SHT_REL)
			{
				if (!slurp_rel_relocs (aux->file, relsec->sh_offset,
									   relsec->sh_size,
									   & arm_sec->rela, & arm_sec->nrelas))
					return FALSE;
				break;
			}
			else if (relsec->sh_type == SHT_RELA)
			{
				if (!slurp_rela_relocs (aux->file, relsec->sh_offset,
										relsec->sh_size,
										& arm_sec->rela, & arm_sec->nrelas))
					return FALSE;
				break;
			}
			else
				warn (("unexpected relocation type (%d) for section %d"),
					  relsec->sh_type, relsec->sh_info);
		}

		arm_sec->next_rela = arm_sec->rela;
	}

	/* If there is no unwind data we can do nothing.  */
	if (arm_sec->data == NULL)
		return FALSE;

	/* Get the word at the required offset.  */
	word = byte_get (arm_sec->data + word_offset, 4);

	/* Look through the relocs to find the one that applies to the provided offset.  */
	wrapped = FALSE;
	for (rp = arm_sec->next_rela; rp != arm_sec->rela + arm_sec->nrelas; rp++)
	{
		bfd_vma prelval, offset;

		if (rp->r_offset > word_offset && !wrapped)
		{
			rp = arm_sec->rela;
			wrapped = TRUE;
		}
		if (rp->r_offset > word_offset)
			break;

		if (rp->r_offset & 3)
		{
			warn (("Skipping unexpected relocation at offset 0x%lx\n"),
				  (unsigned long) rp->r_offset);
			continue;
		}

		if (rp->r_offset < word_offset)
			continue;

		sym = aux->symtab + ELF32_R_SYM (rp->r_info);

		if (arm_sec->rel_type == SHT_REL)
		{
			offset = word & 0x7fffffff;
			if (offset & 0x40000000)
				offset |= ~ (bfd_vma) 0x7fffffff;
		}
		else if (arm_sec->rel_type == SHT_RELA)
			offset = rp->r_addend;
		else
			abort ();

		offset += sym->st_value;
		prelval = offset - (arm_sec->sec->sh_addr + rp->r_offset);

		/* Check that we are processing the expected reloc type.  */
		if (elf_header.e_machine == EM_ARM)
		{
			relname = elf_arm_reloc_type (ELF32_R_TYPE (rp->r_info));

			if (streq (relname, "R_ARM_NONE"))
				continue;

			if (! streq (relname, "R_ARM_PREL31"))
			{
				warn (("Skipping unexpected relocation type %s\n"), relname);
				continue;
			}
		}
		else if (elf_header.e_machine == EM_TI_C6000)
		{
			relname = elf_tic6x_reloc_type (ELF32_R_TYPE (rp->r_info));

			if (streq (relname, "R_C6000_NONE"))
				continue;

			if (! streq (relname, "R_C6000_PREL31"))
			{
				warn (("Skipping unexpected relocation type %s\n"), relname);
				continue;
			}

			prelval >>= 1;
		}
		else
			/* This function currently only supports ARM and TI unwinders.  */
			abort ();

		word = (word & ~ (bfd_vma) 0x7fffffff) | (prelval & 0x7fffffff);
		addr->section = sym->st_shndx;
		addr->offset = offset;
		if (sym_name)
			* sym_name = sym->st_name;
		break;
	}

	*wordp = word;
	arm_sec->next_rela = rp;

	return TRUE;
}


#define ADVANCE							\
  if (remaining == 0 && more_words)				\
    {								\
      data_offset += 4;						\
      if (! get_unwind_section_word (aux, data_arm_sec, data_sec,	\
				     data_offset, & word, & addr, NULL))	\
	return;							\
      remaining = 4;						\
      more_words--;						\
    }								\
 
#define GET_OP(OP)			\
  ADVANCE;				\
  if (remaining)			\
    {					\
      remaining--;			\
      (OP) = word >> 24;		\
      word <<= 8;			\
    }					\
  else					\
    {					\
      printf (("[Truncated opcode]\n"));	\
      return;				\
    }					\
  printf ("0x%02x ", OP)

static void
decode_arm_unwind_bytecode (struct arm_unw_aux_info *aux,
							unsigned int word, unsigned int remaining,
							unsigned int more_words,
							bfd_vma data_offset, Elf_Internal_Shdr *data_sec,
							struct arm_section *data_arm_sec)
{
	struct absaddr addr;

	/* Decode the unwinding instructions.  */
	while (1)
	{
		unsigned int op, op2;

		ADVANCE;
		if (remaining == 0)
			break;
		remaining--;
		op = word >> 24;
		word <<= 8;

		printf ("  0x%02x ", op);

		if ((op & 0xc0) == 0x00)
		{
			int offset = ((op & 0x3f) << 2) + 4;

			printf ("     vsp = vsp + %d", offset);
		}
		else if ((op & 0xc0) == 0x40)
		{
			int offset = ((op & 0x3f) << 2) + 4;

			printf ("     vsp = vsp - %d", offset);
		}
		else if ((op & 0xf0) == 0x80)
		{
			GET_OP (op2);
			if (op == 0x80 && op2 == 0)
				printf (("Refuse to unwind"));
			else
			{
				unsigned int mask = ((op & 0x0f) << 8) | op2;
				int first = 1;
				int i;

				printf ("pop {");
				for (i = 0; i < 12; i++)
					if (mask & (1 << i))
					{
						if (first)
							first = 0;
						else
							printf (", ");
						printf ("r%d", 4 + i);
					}
				printf ("}");
			}
		}
		else if ((op & 0xf0) == 0x90)
		{
			if (op == 0x9d || op == 0x9f)
				printf (("     [Reserved]"));
			else
				printf ("     vsp = r%d", op & 0x0f);
		}
		else if ((op & 0xf0) == 0xa0)
		{
			int end = 4 + (op & 0x07);
			int first = 1;
			int i;

			printf ("     pop {");
			for (i = 4; i <= end; i++)
			{
				if (first)
					first = 0;
				else
					printf (", ");
				printf ("r%d", i);
			}
			if (op & 0x08)
			{
				if (!first)
					printf (", ");
				printf ("r14");
			}
			printf ("}");
		}
		else if (op == 0xb0)
			printf (("     finish"));
		else if (op == 0xb1)
		{
			GET_OP (op2);
			if (op2 == 0 || (op2 & 0xf0) != 0)
				printf (("[Spare]"));
			else
			{
				unsigned int mask = op2 & 0x0f;
				int first = 1;
				int i;

				printf ("pop {");
				for (i = 0; i < 12; i++)
					if (mask & (1 << i))
					{
						if (first)
							first = 0;
						else
							printf (", ");
						printf ("r%d", i);
					}
				printf ("}");
			}
		}
		else if (op == 0xb2)
		{
			unsigned char buf[9];
			unsigned int i, len;
			unsigned long offset;

			for (i = 0; i < sizeof (buf); i++)
			{
				GET_OP (buf[i]);
				if ((buf[i] & 0x80) == 0)
					break;
			}
			assert (i < sizeof (buf));
			offset = read_uleb128 (buf, &len);
			assert (len == i + 1);
			offset = offset * 4 + 0x204;
			printf ("vsp = vsp + %ld", offset);
		}
		else if (op == 0xb3 || op == 0xc8 || op == 0xc9)
		{
			unsigned int first, last;

			GET_OP (op2);
			first = op2 >> 4;
			last = op2 & 0x0f;
			if (op == 0xc8)
				first = first + 16;
			printf ("pop {D%d", first);
			if (last)
				printf ("-D%d", first + last);
			printf ("}");
		}
		else if ((op & 0xf8) == 0xb8 || (op & 0xf8) == 0xd0)
		{
			unsigned int count = op & 0x07;

			printf ("pop {D8");
			if (count)
				printf ("-D%d", 8 + count);
			printf ("}");
		}
		else if (op >= 0xc0 && op <= 0xc5)
		{
			unsigned int count = op & 0x07;

			printf ("     pop {wR10");
			if (count)
				printf ("-wR%d", 10 + count);
			printf ("}");
		}
		else if (op == 0xc6)
		{
			unsigned int first, last;

			GET_OP (op2);
			first = op2 >> 4;
			last = op2 & 0x0f;
			printf ("pop {wR%d", first);
			if (last)
				printf ("-wR%d", first + last);
			printf ("}");
		}
		else if (op == 0xc7)
		{
			GET_OP (op2);
			if (op2 == 0 || (op2 & 0xf0) != 0)
				printf (("[Spare]"));
			else
			{
				unsigned int mask = op2 & 0x0f;
				int first = 1;
				int i;

				printf ("pop {");
				for (i = 0; i < 4; i++)
					if (mask & (1 << i))
					{
						if (first)
							first = 0;
						else
							printf (", ");
						printf ("wCGR%d", i);
					}
				printf ("}");
			}
		}
		else
			printf (("     [unsupported opcode]"));
		printf ("\n");
	}
}


static bfd_vma
arm_expand_prel31 (bfd_vma word, bfd_vma where)
{
	bfd_vma offset;

	offset = word & 0x7fffffff;
	if (offset & 0x40000000)
		offset |= ~ (bfd_vma) 0x7fffffff;

	if (elf_header.e_machine == EM_TI_C6000)
		offset <<= 1;

	return offset + where;
}

static void
decode_arm_unwind (struct arm_unw_aux_info *  aux,
				   unsigned int               word,
				   unsigned int               remaining,
				   bfd_vma                    data_offset,
				   Elf_Internal_Shdr *        data_sec,
				   struct arm_section *       data_arm_sec)
{
	int per_index;
	unsigned int more_words = 0;
	struct absaddr addr;
	bfd_vma sym_name = (bfd_vma) -1;

	if (remaining == 0)
	{
		/* Fetch the first word.
		Note - when decoding an object file the address extracted
		 here will always be 0.  So we also pass in the sym_name
		 parameter so that we can find the symbol associated with
		 the personality routine.  */
		if (! get_unwind_section_word (aux, data_arm_sec, data_sec, data_offset,
									   & word, & addr, & sym_name))
			return;

		remaining = 4;
	}

	if ((word & 0x80000000) == 0)
	{
		/* Expand prel31 for personality routine.  */
		bfd_vma fn;
		const char *procname;

		fn = arm_expand_prel31 (word, data_sec->sh_addr + data_offset);
		printf (("  Personality routine: "));
		if (fn == 0
				&& addr.section == SHN_UNDEF && addr.offset == 0
				&& sym_name != (bfd_vma) -1 && sym_name < aux->strtab_size)
		{
			procname = aux->strtab + sym_name;
			print_vma (fn, PREFIX_HEX);
			if (procname)
			{
				fputs (" <", stdout);
				fputs (procname, stdout);
				fputc ('>', stdout);
			}
		}
		else
			procname = arm_print_vma_and_name (aux, fn, addr);
		fputc ('\n', stdout);

		/* The GCC personality routines use the standard compact
		encoding, starting with one byte giving the number of
		 words.  */
		if (procname != NULL
				&& (const_strneq (procname, "__gcc_personality_v0")
					|| const_strneq (procname, "__gxx_personality_v0")
					|| const_strneq (procname, "__gcj_personality_v0")
					|| const_strneq (procname, "__gnu_objc_personality_v0")))
		{
			remaining = 0;
			more_words = 1;
			ADVANCE;
			if (!remaining)
			{
				printf (("  [Truncated data]\n"));
				return;
			}
			more_words = word >> 24;
			word <<= 8;
			remaining--;
			per_index = -1;
		}
		else
			return;
	}
	else
	{
		/* ARM EHABI Section 6.3:

		An exception-handling table entry for the compact model looks like:

		         31 30-28 27-24 23-0
		   -- ----- ----- ----
		          1   0   index Data for personalityRoutine[index]    */

		if (elf_header.e_machine == EM_ARM
				&& (word & 0x70000000))
			warn (("Corrupt ARM compact model table entry: %x \n"), word);

		per_index = (word >> 24) & 0x7f;
		printf (("  Compact model index: %d\n"), per_index);
		if (per_index == 0)
		{
			more_words = 0;
			word <<= 8;
			remaining--;
		}
		else if (per_index < 3)
		{
			more_words = (word >> 16) & 0xff;
			word <<= 16;
			remaining -= 2;
		}
	}

	switch (elf_header.e_machine)
	{
	case EM_ARM:
		if (per_index < 3)
		{
			decode_arm_unwind_bytecode (aux, word, remaining, more_words,
										data_offset, data_sec, data_arm_sec);
		}
		else
		{
			warn (("Unknown ARM compact model index encountered\n"));
			printf (("  [reserved]\n"));
		}
		break;

	case EM_TI_C6000:
		if (per_index < 3)
		{
			decode_tic6x_unwind_bytecode (aux, word, remaining, more_words,
										  data_offset, data_sec, data_arm_sec);
		}
		else if (per_index < 5)
		{
			if (((word >> 17) & 0x7f) == 0x7f)
				printf (("  Restore stack from frame pointer\n"));
			else
				printf (("  Stack increment %d\n"), (word >> 14) & 0x1fc);
			printf (("  Registers restored: "));
			if (per_index == 4)
				printf (" (compact) ");
			decode_tic6x_unwind_regmask ((word >> 4) & 0x1fff);
			putchar ('\n');
			printf (("  Return register: %s\n"),
					tic6x_unwind_regnames[word & 0xf]);
		}
		else
			printf (("  [reserved (%d)]\n"), per_index);
		break;

	default:
		printf (("Unsupported architecture type %d encountered when decoding unwind table"),
			   elf_header.e_machine);
	}

	/* Decode the descriptors.  Not implemented.  */
}

static void
dump_arm_unwind (struct arm_unw_aux_info *aux, Elf_Internal_Shdr *exidx_sec)
{
	struct arm_section exidx_arm_sec, extab_arm_sec;
	unsigned int i, exidx_len;

	memset (&exidx_arm_sec, 0, sizeof (exidx_arm_sec));
	memset (&extab_arm_sec, 0, sizeof (extab_arm_sec));
	exidx_len = exidx_sec->sh_size / 8;

	for (i = 0; i < exidx_len; i++)
	{
		unsigned int exidx_fn, exidx_entry;
		struct absaddr fn_addr, entry_addr;
		bfd_vma fn;

		fputc ('\n', stdout);

		if (! get_unwind_section_word (aux, & exidx_arm_sec, exidx_sec,
									   8 * i, & exidx_fn, & fn_addr, NULL)
				|| ! get_unwind_section_word (aux, & exidx_arm_sec, exidx_sec,
											  8 * i + 4, & exidx_entry, & entry_addr, NULL))
		{
			arm_free_section (& exidx_arm_sec);
			arm_free_section (& extab_arm_sec);
			return;
		}

		/* ARM EHABI, Section 5:
		An index table entry consists of 2 words.
		       The first word contains a prel31 offset to the start of a function, with bit 31 clear.  */
		if (exidx_fn & 0x80000000)
			warn (("corrupt index table entry: %x\n"), exidx_fn);

		fn = arm_expand_prel31 (exidx_fn, exidx_sec->sh_addr + 8 * i);

		arm_print_vma_and_name (aux, fn, fn_addr);
		fputs (": ", stdout);

		if (exidx_entry == 1)
		{
			print_vma (exidx_entry, PREFIX_HEX);
			fputs (" [cantunwind]\n", stdout);
		}
		else if (exidx_entry & 0x80000000)
		{
			print_vma (exidx_entry, PREFIX_HEX);
			fputc ('\n', stdout);
			decode_arm_unwind (aux, exidx_entry, 4, 0, NULL, NULL);
		}
		else
		{
			bfd_vma table, table_offset = 0;
			Elf_Internal_Shdr *table_sec;

			fputs ("@", stdout);
			table = arm_expand_prel31 (exidx_entry, exidx_sec->sh_addr + 8 * i + 4);
			print_vma (table, PREFIX_HEX);
			printf ("\n");

			/* Locate the matching .ARM.extab.  */
			if (entry_addr.section != SHN_UNDEF
					&& entry_addr.section < elf_header.e_shnum)
			{
				table_sec = section_headers + entry_addr.section;
				table_offset = entry_addr.offset;
			}
			else
			{
				table_sec = find_section_by_address (table);
				if (table_sec != NULL)
					table_offset = table - table_sec->sh_addr;
			}
			if (table_sec == NULL)
			{
				warn (("Could not locate .ARM.extab section containing 0x%lx.\n"),
					  (unsigned long) table);
				continue;
			}
			decode_arm_unwind (aux, 0, 0, table_offset, table_sec,
							   &extab_arm_sec);
		}
	}

	printf ("\n");

	arm_free_section (&exidx_arm_sec);
	arm_free_section (&extab_arm_sec);
}

#endif
#if 0
#ifdef BFD64

/* VMS vs Unix time offset and factor.  */

#define VMS_EPOCH_OFFSET 35067168000000000LL
#define VMS_GRANULARITY_FACTOR 10000000

/* Display a VMS time in a human readable format.  */

static void
print_vms_time (bfd_int64_t vmstime)
{
	struct tm *tm;
	time_t unxtime;

	unxtime = (vmstime - VMS_EPOCH_OFFSET) / VMS_GRANULARITY_FACTOR;
	tm = gmtime (&unxtime);
	printf ("%04u-%02u-%02uT%02u:%02u:%02u",
			tm->tm_year + 1900, tm->tm_mon + 1, tm->tm_mday,
			tm->tm_hour, tm->tm_min, tm->tm_sec);
}
#endif /* BFD64 */

#endif

static int
get_dynamic_section (FILE * file)
{
	Elf_External_Dyn * edyn;
	Elf_External_Dyn * ext;
	Elf_Internal_Dyn * entry;

	edyn = (Elf_External_Dyn *) get_data (NULL, file, dynamic_addr, 1,
											dynamic_size, ("dynamic section"));
	if (!edyn)
		return 0;

	/* SGI's ELF has more than one section in the DYNAMIC segment, and we
	   might not have the luxury of section headers.  Look for the DT_NULL
	   terminator to determine the number of entries.  */
	for (ext = edyn, dynamic_nent = 0;
			(char *) ext < (char *) edyn + dynamic_size;
			ext++)
	{
		dynamic_nent++;
		if (BYTE_GET (ext->d_tag) == DT_NULL)
			break;
	}

	dynamic_section = (Elf_Internal_Dyn *) cmalloc (dynamic_nent,
					  sizeof (* entry));
	if (dynamic_section == NULL)
	{
		printf ("Out of memory\n");
		free (edyn);
		return 0;
	}

	for (ext = edyn, entry = dynamic_section;
			entry < dynamic_section + dynamic_nent;
			ext++, entry++)
	{
		entry->d_tag      = BYTE_GET (ext->d_tag);
		entry->d_un.d_val = BYTE_GET (ext->d_un.d_val);
	}

	free (edyn);

	return 1;
}

#if 0
static void
print_dynamic_flags (bfd_vma flags)
{
	int first = 1;

	while (flags)
	{
		bfd_vma flag;

		flag = flags & - flags;
		flags &= ~ flag;

		if (first)
			first = 0;
		else
			putc (' ', stdout);

		switch (flag)
		{
		case DF_ORIGIN:
			fputs ("ORIGIN", stdout);
			break;
		case DF_SYMBOLIC:
			fputs ("SYMBOLIC", stdout);
			break;
		case DF_TEXTREL:
			fputs ("TEXTREL", stdout);
			break;
		case DF_BIND_NOW:
			fputs ("BIND_NOW", stdout);
			break;
		case DF_STATIC_TLS:
			fputs ("STATIC_TLS", stdout);
			break;
		default:
			fputs (("unknown"), stdout);
			break;
		}
	}
	puts ("");
}
#endif
/* Parse and display the contents of the dynamic section.  */

static int
process_dynamic_section (FILE * file)
{
	Elf_Internal_Dyn * entry;

	if (dynamic_size == 0)
	{
		if (do_dynamic)
			printf ("\nThere is no dynamic section in this file.\n");

		return 1;
	}

	if (! get_dynamic_section (file))
		return 0;

	/* Find the appropriate symbol table.  */
	if (dynamic_symbols == NULL)
	{
		for (entry = dynamic_section;
				entry < dynamic_section + dynamic_nent;
				++entry)
		{
			Elf_Internal_Shdr section;

			if (entry->d_tag != DT_SYMTAB)
				continue;

			dynamic_info[DT_SYMTAB] = entry->d_un.d_val;

			/* Since we do not know how big the symbol table is,
			   we default to reading in the entire file (!) and
			   processing that.  This is overkill, I know, but it
			   should work.  */
			section.sh_offset = offset_from_vma (file, entry->d_un.d_val, 0);

			if (archive_file_offset != 0)
				section.sh_size = archive_file_size - section.sh_offset;
			else
			{
				if (fseek (file, 0, SEEK_END))
					printf (("Unable to seek to end of file!\n"));

				section.sh_size = ftell (file) - section.sh_offset;
			}

			section.sh_entsize = sizeof (Elf_External_Sym);

			dynamic_symbols = get_elf_symbols (file, &section, & num_dynamic_syms);
			if (num_dynamic_syms < 1)
			{
				printf ("Unable to determine the number of symbols to load\n");
				continue;
			}
		}
	}

	/* Similarly find a string table.  */
	if (dynamic_strings == NULL)
	{
		for (entry = dynamic_section;
				entry < dynamic_section + dynamic_nent;
				++entry)
		{
			unsigned long offset;
			long str_tab_len;

			if (entry->d_tag != DT_STRTAB)
				continue;

			dynamic_info[DT_STRTAB] = entry->d_un.d_val;

			/* Since we do not know how big the string table is,
			   we default to reading in the entire file (!) and
			   processing that.  This is overkill, I know, but it
			   should work.  */

			offset = offset_from_vma (file, entry->d_un.d_val, 0);

			if (archive_file_offset != 0)
				str_tab_len = archive_file_size - offset;
			else
			{
				if (fseek (file, 0, SEEK_END))
					printf ("Unable to seek to end of file\n");
				str_tab_len = ftell (file) - offset;
			}

			if (str_tab_len < 1)
			{
				//error
				//("Unable to determine the length of the dynamic string table\n");
				continue;
			}

			dynamic_strings = (char *) get_data (NULL, file, offset, 1,
												 str_tab_len,
												 ("dynamic string table"));
			dynamic_strings_length = dynamic_strings == NULL ? 0 : str_tab_len;
			break;
		}
	}

	/* And find the syminfo section if available.  */
	if (dynamic_syminfo == NULL)
	{
		unsigned long syminsz = 0;

		for (entry = dynamic_section;
				entry < dynamic_section + dynamic_nent;
				++entry)
		{
			if (entry->d_tag == DT_SYMINENT)
			{
				/* Note: these braces are necessary to avoid a syntax
				error from the SunOS4 C compiler.  */
				//assert (sizeof (Elf_External_Syminfo) == entry->d_un.d_val);
			}
			else if (entry->d_tag == DT_SYMINSZ)
				syminsz = entry->d_un.d_val;
			else if (entry->d_tag == DT_SYMINFO)
				dynamic_syminfo_offset = offset_from_vma (file, entry->d_un.d_val,
										 syminsz);
		}

		if (dynamic_syminfo_offset != 0 && syminsz != 0)
		{
			Elf_External_Syminfo * extsyminfo;
			Elf_External_Syminfo * extsym;
			Elf_Internal_Syminfo * syminfo;

			/* There is a syminfo section.  Read the data.  */
			extsyminfo = (Elf_External_Syminfo *)
						 get_data (NULL, file, dynamic_syminfo_offset, 1, syminsz,
								   ("symbol information"));
			if (!extsyminfo)
				return 0;

			dynamic_syminfo = (Elf_Internal_Syminfo *) malloc (syminsz);
			if (dynamic_syminfo == NULL)
			{
				printf (("Out of memory\n"));
				return 0;
			}

			dynamic_syminfo_nent = syminsz / sizeof (Elf_External_Syminfo);
			for (syminfo = dynamic_syminfo, extsym = extsyminfo;
					syminfo < dynamic_syminfo + dynamic_syminfo_nent;
					++syminfo, ++extsym)
			{
				syminfo->si_boundto = BYTE_GET (extsym->si_boundto);
				syminfo->si_flags = BYTE_GET (extsym->si_flags);
			}

			free (extsyminfo);
		}
	}

	if (do_dynamic && dynamic_addr)
		printf (("\nDynamic section at offset 0x%lx contains %u entries:\n"),
				dynamic_addr, dynamic_nent);
	if (do_dynamic)
		printf (("  Tag        Type                         Name/Value\n"));

#if 0
	for (entry = dynamic_section;
			entry < dynamic_section + dynamic_nent;
			entry++)
	{
		if (do_dynamic)
		{
			const char * dtype;

			putchar (' ');
			print_vma (entry->d_tag, FULL_HEX);
			dtype = get_dynamic_type (entry->d_tag);
			printf (" (%s)%*s", dtype,
					((is_32bit_elf ? 27 : 19)
					 - (int) strlen (dtype)),
					" ");
		}

		switch (entry->d_tag)
		{
		case DT_FLAGS:
			if (do_dynamic)
				print_dynamic_flags (entry->d_un.d_val);
			break;

		case DT_AUXILIARY:
		case DT_FILTER:
		case DT_CONFIG:
		case DT_DEPAUDIT:
		case DT_AUDIT:
			if (do_dynamic)
			{
				switch (entry->d_tag)
				{
				case DT_AUXILIARY:
					printf (("Auxiliary library"));
					break;

				case DT_FILTER:
					printf (("Filter library"));
					break;

				case DT_CONFIG:
					printf (("Configuration file"));
					break;

				case DT_DEPAUDIT:
					printf (("Dependency audit library"));
					break;

				case DT_AUDIT:
					printf (("Audit library"));
					break;
				}

				if (VALID_DYNAMIC_NAME (entry->d_un.d_val))
					printf (": [%s]\n", GET_DYNAMIC_NAME (entry->d_un.d_val));
				else
				{
					printf (": ");
					print_vma (entry->d_un.d_val, PREFIX_HEX);
					putchar ('\n');
				}
			}
			break;

		case DT_FEATURE:
			if (do_dynamic)
			{
				printf (("Flags:"));

				if (entry->d_un.d_val == 0)
					printf ((" None\n"));
				else
				{
					unsigned long int val = entry->d_un.d_val;

					if (val & DTF_1_PARINIT)
					{
						printf (" PARINIT");
						val ^= DTF_1_PARINIT;
					}
					if (val & DTF_1_CONFEXP)
					{
						printf (" CONFEXP");
						val ^= DTF_1_CONFEXP;
					}
					if (val != 0)
						printf (" %lx", val);
					puts ("");
				}
			}
			break;

		case DT_POSFLAG_1:
			if (do_dynamic)
			{
				printf (("Flags:"));

				if (entry->d_un.d_val == 0)
					printf ((" None\n"));
				else
				{
					unsigned long int val = entry->d_un.d_val;

					if (val & DF_P1_LAZYLOAD)
					{
						printf (" LAZYLOAD");
						val ^= DF_P1_LAZYLOAD;
					}
					if (val & DF_P1_GROUPPERM)
					{
						printf (" GROUPPERM");
						val ^= DF_P1_GROUPPERM;
					}
					if (val != 0)
						printf (" %lx", val);
					puts ("");
				}
			}
			break;

		case DT_FLAGS_1:
			if (do_dynamic)
			{
				printf (("Flags:"));
				if (entry->d_un.d_val == 0)
					printf ((" None\n"));
				else
				{
					unsigned long int val = entry->d_un.d_val;

					if (val & DF_1_NOW)
					{
						printf (" NOW");
						val ^= DF_1_NOW;
					}
					if (val & DF_1_GLOBAL)
					{
						printf (" GLOBAL");
						val ^= DF_1_GLOBAL;
					}
					if (val & DF_1_GROUP)
					{
						printf (" GROUP");
						val ^= DF_1_GROUP;
					}
					if (val & DF_1_NODELETE)
					{
						printf (" NODELETE");
						val ^= DF_1_NODELETE;
					}
					if (val & DF_1_LOADFLTR)
					{
						printf (" LOADFLTR");
						val ^= DF_1_LOADFLTR;
					}
					if (val & DF_1_INITFIRST)
					{
						printf (" INITFIRST");
						val ^= DF_1_INITFIRST;
					}
					if (val & DF_1_NOOPEN)
					{
						printf (" NOOPEN");
						val ^= DF_1_NOOPEN;
					}
					if (val & DF_1_ORIGIN)
					{
						printf (" ORIGIN");
						val ^= DF_1_ORIGIN;
					}
					if (val & DF_1_DIRECT)
					{
						printf (" DIRECT");
						val ^= DF_1_DIRECT;
					}
					if (val & DF_1_TRANS)
					{
						printf (" TRANS");
						val ^= DF_1_TRANS;
					}
					if (val & DF_1_INTERPOSE)
					{
						printf (" INTERPOSE");
						val ^= DF_1_INTERPOSE;
					}
					if (val & DF_1_NODEFLIB)
					{
						printf (" NODEFLIB");
						val ^= DF_1_NODEFLIB;
					}
					if (val & DF_1_NODUMP)
					{
						printf (" NODUMP");
						val ^= DF_1_NODUMP;
					}
					if (val & DF_1_CONLFAT)
					{
						printf (" CONLFAT");
						val ^= DF_1_CONLFAT;
					}
					if (val != 0)
						printf (" %lx", val);
					puts ("");
				}
			}
			break;

		case DT_PLTREL:
			dynamic_info[entry->d_tag] = entry->d_un.d_val;
			if (do_dynamic)
				puts (get_dynamic_type (entry->d_un.d_val));
			break;

		case DT_NULL	:
		case DT_NEEDED	:
		case DT_PLTGOT	:
		case DT_HASH	:
		case DT_STRTAB	:
		case DT_SYMTAB	:
		case DT_RELA	:
		case DT_INIT	:
		case DT_FINI	:
		case DT_SONAME	:
		case DT_RPATH	:
		case DT_SYMBOLIC:
		case DT_REL	:
		case DT_DEBUG	:
		case DT_TEXTREL	:
		case DT_JMPREL	:
		case DT_RUNPATH	:
			dynamic_info[entry->d_tag] = entry->d_un.d_val;

			if (do_dynamic)
			{
				char * name;

				if (VALID_DYNAMIC_NAME (entry->d_un.d_val))
					name = GET_DYNAMIC_NAME (entry->d_un.d_val);
				else
					name = NULL;

				if (name)
				{
					switch (entry->d_tag)
					{
					case DT_NEEDED:
						printf (("Shared library: [%s]"), name);

						if (streq (name, program_interpreter))
							printf ((" program interpreter"));
						break;

					case DT_SONAME:
						printf (("Library soname: [%s]"), name);
						break;

					case DT_RPATH:
						printf (("Library rpath: [%s]"), name);
						break;

					case DT_RUNPATH:
						printf (("Library runpath: [%s]"), name);
						break;

					default:
						print_vma (entry->d_un.d_val, PREFIX_HEX);
						break;
					}
				}
				else
					print_vma (entry->d_un.d_val, PREFIX_HEX);

				putchar ('\n');
			}
			break;

		case DT_PLTRELSZ:
		case DT_RELASZ	:
		case DT_STRSZ	:
		case DT_RELSZ	:
		case DT_RELAENT	:
		case DT_SYMENT	:
		case DT_RELENT	:
			dynamic_info[entry->d_tag] = entry->d_un.d_val;
		case DT_PLTPADSZ:
		case DT_MOVEENT	:
		case DT_MOVESZ	:
		case DT_INIT_ARRAYSZ:
		case DT_FINI_ARRAYSZ:
		case DT_GNU_CONFLICTSZ:
		case DT_GNU_LIBLISTSZ:
			if (do_dynamic)
			{
				print_vma (entry->d_un.d_val, UNSIGNED);
				printf ((" (bytes)\n"));
			}
			break;

		case DT_VERDEFNUM:
		case DT_VERNEEDNUM:
		case DT_RELACOUNT:
		case DT_RELCOUNT:
			if (do_dynamic)
			{
				print_vma (entry->d_un.d_val, UNSIGNED);
				putchar ('\n');
			}
			break;

		case DT_SYMINSZ:
		case DT_SYMINENT:
		case DT_SYMINFO:
		case DT_USED:
		case DT_INIT_ARRAY:
		case DT_FINI_ARRAY:
			if (do_dynamic)
			{
				if (entry->d_tag == DT_USED
						&& VALID_DYNAMIC_NAME (entry->d_un.d_val))
				{
					char * name = GET_DYNAMIC_NAME (entry->d_un.d_val);

					if (*name)
					{
						printf (("Not needed object: [%s]\n"), name);
						break;
					}
				}

				print_vma (entry->d_un.d_val, PREFIX_HEX);
				putchar ('\n');
			}
			break;

		case DT_BIND_NOW:
			/* The value of this entry is ignored.  */
			if (do_dynamic)
				putchar ('\n');
			break;

		case DT_GNU_PRELINKED:
			if (do_dynamic)
			{
				struct tm * tmp;
				time_t atime = entry->d_un.d_val;

				tmp = gmtime (&atime);
				printf ("%04u-%02u-%02uT%02u:%02u:%02u\n",
						tmp->tm_year + 1900, tmp->tm_mon + 1, tmp->tm_mday,
						tmp->tm_hour, tmp->tm_min, tmp->tm_sec);

			}
			break;

		case DT_GNU_HASH:
			dynamic_info_DT_GNU_HASH = entry->d_un.d_val;
			if (do_dynamic)
			{
				print_vma (entry->d_un.d_val, PREFIX_HEX);
				putchar ('\n');
			}
			break;

		default:
			if ((entry->d_tag >= DT_VERSYM) && (entry->d_tag <= DT_VERNEEDNUM))
				version_info[DT_VERSIONTAGIDX (entry->d_tag)] =
					entry->d_un.d_val;

			if (do_dynamic)
			{
				switch (elf_header.e_machine)
				{
				case EM_MIPS:
				case EM_MIPS_RS3_LE:
					dynamic_section_mips_val (entry);
					break;
				case EM_PARISC:
					dynamic_section_parisc_val (entry);
					break;
				case EM_IA_64:
					dynamic_section_ia64_val (entry);
					break;
				default:
					print_vma (entry->d_un.d_val, PREFIX_HEX);
					putchar ('\n');
				}
			}
			break;
		}
	}
#endif
	return 1;
}
#if 0
static char *
get_ver_flags (unsigned int flags)
{
	static char buff[32];

	buff[0] = 0;

	if (flags == 0)
		return ("none");

	if (flags & VER_FLG_BASE)
		strcat (buff, "BASE ");

	if (flags & VER_FLG_WEAK)
	{
		if (flags & VER_FLG_BASE)
			strcat (buff, "| ");

		strcat (buff, "WEAK ");
	}

	if (flags & VER_FLG_INFO)
	{
		if (flags & (VER_FLG_BASE|VER_FLG_WEAK))
			strcat (buff, "| ");

		strcat (buff, "INFO ");
	}

	if (flags & ~(VER_FLG_BASE | VER_FLG_WEAK | VER_FLG_INFO))
		strcat (buff, ("| <unknown>"));

	return buff;
}

static const char *
get_symbol_binding (unsigned int binding)
{
	static char buff[32];

	switch (binding)
	{
	case STB_LOCAL:
		return "LOCAL";
	case STB_GLOBAL:
		return "GLOBAL";
	case STB_WEAK:
		return "WEAK";
	default:
		if (binding >= STB_LOPROC && binding <= STB_HIPROC)
			snprintf (buff, sizeof (buff), ("<processor specific>: %d"),
					  binding);
		else if (binding >= STB_LOOS && binding <= STB_HIOS)
		{
			if (binding == STB_GNU_UNIQUE
					&& (elf_header.e_ident[EI_OSABI] == ELFOSABI_GNU
						/* GNU is still using the default value 0.  */
						|| elf_header.e_ident[EI_OSABI] == ELFOSABI_NONE))
				return "UNIQUE";
			snprintf (buff, sizeof (buff), ("<OS specific>: %d"), binding);
		}
		else
			snprintf (buff, sizeof (buff), ("<unknown>: %d"), binding);
		return buff;
	}
}

static const char *
get_symbol_type (unsigned int type)
{
	static char buff[32];

	switch (type)
	{
	case STT_NOTYPE:
		return "NOTYPE";
	case STT_OBJECT:
		return "OBJECT";
	case STT_FUNC:
		return "FUNC";
	case STT_SECTION:
		return "SECTION";
	case STT_FILE:
		return "FILE";
	case STT_COMMON:
		return "COMMON";
	case STT_TLS:
		return "TLS";
	case STT_RELC:
		return "RELC";
	case STT_SRELC:
		return "SRELC";
	default:
		if (type >= STT_LOPROC && type <= STT_HIPROC)
		{
			if (elf_header.e_machine == EM_ARM && type == STT_ARM_TFUNC)
				return "THUMB_FUNC";

			if (elf_header.e_machine == EM_SPARCV9 && type == STT_REGISTER)
				return "REGISTER";

			if (elf_header.e_machine == EM_PARISC && type == STT_PARISC_MILLI)
				return "PARISC_MILLI";

			snprintf (buff, sizeof (buff), ("<processor specific>: %d"), type);
		}
		else if (type >= STT_LOOS && type <= STT_HIOS)
		{
			if (elf_header.e_machine == EM_PARISC)
			{
				if (type == STT_HP_OPAQUE)
					return "HP_OPAQUE";
				if (type == STT_HP_STUB)
					return "HP_STUB";
			}

			if (type == STT_GNU_IFUNC
					&& (elf_header.e_ident[EI_OSABI] == ELFOSABI_GNU
						|| elf_header.e_ident[EI_OSABI] == ELFOSABI_FREEBSD
						/* GNU is still using the default value 0.  */
						|| elf_header.e_ident[EI_OSABI] == ELFOSABI_NONE))
				return "IFUNC";

			snprintf (buff, sizeof (buff), ("<OS specific>: %d"), type);
		}
		else
			snprintf (buff, sizeof (buff), ("<unknown>: %d"), type);
		return buff;
	}
}

static const char *
get_symbol_visibility (unsigned int visibility)
{
	switch (visibility)
	{
	case STV_DEFAULT:
		return "DEFAULT";
	case STV_INTERNAL:
		return "INTERNAL";
	case STV_HIDDEN:
		return "HIDDEN";
	case STV_PROTECTED:
		return "PROTECTED";
	default:
		abort ();
	}
}

static const char *
get_symbol_other (unsigned int other)
{
	const char * result = NULL;
	static char buff [32];

	if (other == 0)
		return "";

	if (result)
		return result;

	snprintf (buff, sizeof buff, ("<other>: %x"), other);
	return buff;
}

static const char *
get_symbol_index_type (unsigned int type)
{
	static char buff[32];

	switch (type)
	{
	case SHN_UNDEF:
		return "UND";
	case SHN_ABS:
		return "ABS";
	case SHN_COMMON:
		return "COM";
	default:
		if (type == SHN_IA_64_ANSI_COMMON
				&& elf_header.e_machine == EM_IA_64
				&& elf_header.e_ident[EI_OSABI] == ELFOSABI_HPUX)
			return "ANSI_COM";
		else if ((elf_header.e_machine == EM_X86_64
				  || elf_header.e_machine == EM_L1OM
				  || elf_header.e_machine == EM_K1OM)
				 && type == SHN_X86_64_LCOMMON)
			return "LARGE_COM";
		else if ((type == SHN_MIPS_SCOMMON
				  && elf_header.e_machine == EM_MIPS)
				 || (type == SHN_TIC6X_SCOMMON
					 && elf_header.e_machine == EM_TI_C6000))
			return "SCOM";
		else if (type == SHN_MIPS_SUNDEFINED
				 && elf_header.e_machine == EM_MIPS)
			return "SUND";
		else if (type >= SHN_LOPROC && type <= SHN_HIPROC)
			sprintf (buff, "PRC[0x%04x]", type & 0xffff);
		else if (type >= SHN_LOOS && type <= SHN_HIOS)
			sprintf (buff, "OS [0x%04x]", type & 0xffff);
		else if (type >= SHN_LORESERVE)
			sprintf (buff, "RSV[0x%04x]", type & 0xffff);
		else
			sprintf (buff, "%3d", type);
		break;
	}

	return buff;
}
#endif

static bfd_vma *
get_dynamic_data (FILE * file, unsigned int number, unsigned int ent_size)
{
	unsigned char * e_data;
	bfd_vma * i_data;

	e_data = (unsigned char *) cmalloc (number, ent_size);

	if (e_data == NULL)
	{
		printf (("Out of memory\n"));
		return NULL;
	}

	if (fread (e_data, ent_size, number, file) != number)
	{
		printf (("Unable to read in dynamic data\n"));
		return NULL;
	}

	i_data = (bfd_vma *) cmalloc (number, sizeof (*i_data));

	if (i_data == NULL)
	{
		printf (("Out of memory\n"));
		free (e_data);
		return NULL;
	}

	while (number--)
		i_data[number] = byte_get (e_data + number * ent_size, ent_size);

	free (e_data);

	return i_data;
}

static void
print_dynamic_symbol (bfd_vma si, unsigned long hn)
{
#if 0
	Elf_Internal_Sym * psym;
	int n;

	psym = dynamic_symbols + si;

	n = print_vma (si, DEC_5);
	if (n < 5)
		fputs ("     " + n, stdout);
	printf (" %3lu: ", hn);
	print_vma (psym->st_value, LONG_HEX);
	putchar (' ');
	print_vma (psym->st_size, DEC_5);

	printf (" %-7s", get_symbol_type (ELF_ST_TYPE (psym->st_info)));
	printf (" %-6s",  get_symbol_binding (ELF_ST_BIND (psym->st_info)));
	printf (" %-7s",  get_symbol_visibility (ELF_ST_VISIBILITY (psym->st_other)));
	/* Check to see if any other bits in the st_other field are set.
	   Note - displaying this information disrupts the layout of the
	   table being generated, but for the moment this case is very
	   rare.  */
	if (psym->st_other ^ ELF_ST_VISIBILITY (psym->st_other))
		printf (" [%s] ", get_symbol_other (psym->st_other ^ ELF_ST_VISIBILITY (psym->st_other)));
	printf (" %3.3s ", get_symbol_index_type (psym->st_shndx));
	if (VALID_DYNAMIC_NAME (psym->st_name))
		print_symbol (25, GET_DYNAMIC_NAME (psym->st_name));
	else
		printf ((" <corrupt: %14ld>"), psym->st_name);
	putchar ('\n');
#endif
}

/* Dump the symbol table.  */
static int
process_symbol_table (FILE * file)
{
	Elf_Internal_Shdr * section;
	bfd_vma nbuckets = 0;
	bfd_vma nchains = 0;
	bfd_vma * buckets = NULL;
	bfd_vma * chains = NULL;
	bfd_vma ngnubuckets = 0;
	bfd_vma * gnubuckets = NULL;
	bfd_vma * gnuchains = NULL;
	bfd_vma gnusymidx = 0;

	if (dynamic_info[DT_HASH]
			&& (do_histogram
				|| (do_using_dynamic
					&& !do_dyn_syms
					&& dynamic_strings != NULL)))
	{
		unsigned char nb[8];
		unsigned char nc[8];
		int hash_ent_size = 4;

		if (fseek (file,
				   (archive_file_offset
					+ offset_from_vma (file, dynamic_info[DT_HASH],
									   sizeof nb + sizeof nc)),
				   SEEK_SET))
		{
			printf (("Unable to seek to start of dynamic information\n"));
			goto no_hash;
		}

		if (fread (nb, hash_ent_size, 1, file) != 1)
		{
			printf (("Failed to read in number of buckets\n"));
			goto no_hash;
		}

		if (fread (nc, hash_ent_size, 1, file) != 1)
		{
			printf (("Failed to read in number of chains\n"));
			goto no_hash;
		}

		nbuckets = byte_get (nb, hash_ent_size);
		nchains  = byte_get (nc, hash_ent_size);

		buckets = get_dynamic_data (file, nbuckets, hash_ent_size);
		chains  = get_dynamic_data (file, nchains, hash_ent_size);

no_hash:
		if (buckets == NULL || chains == NULL)
		{
			if (do_using_dynamic)
				return 0;
			free (buckets);
			free (chains);
			buckets = NULL;
			chains = NULL;
			nbuckets = 0;
			nchains = 0;
		}
	}

	if (dynamic_info_DT_GNU_HASH
			&& (do_histogram
				|| (do_using_dynamic
					&& !do_dyn_syms
					&& dynamic_strings != NULL)))
	{
		unsigned char nb[16];
		bfd_vma i, maxchain = 0xffffffff, bitmaskwords;
		bfd_vma buckets_vma;

		if (fseek (file,
				   (archive_file_offset
					+ offset_from_vma (file, dynamic_info_DT_GNU_HASH,
									   sizeof nb)),
				   SEEK_SET))
		{
			printf (("Unable to seek to start of dynamic information\n"));
			goto no_gnu_hash;
		}

		if (fread (nb, 16, 1, file) != 1)
		{
			printf (("Failed to read in number of buckets\n"));
			goto no_gnu_hash;
		}

		ngnubuckets = byte_get (nb, 4);
		gnusymidx = byte_get (nb + 4, 4);
		bitmaskwords = byte_get (nb + 8, 4);
		buckets_vma = dynamic_info_DT_GNU_HASH + 16;
		if (is_32bit_elf)
			buckets_vma += bitmaskwords * 4;
		else
			buckets_vma += bitmaskwords * 8;

		if (fseek (file,
				   (archive_file_offset
					+ offset_from_vma (file, buckets_vma, 4)),
				   SEEK_SET))
		{
			printf (("Unable to seek to start of dynamic information\n"));
			goto no_gnu_hash;
		}

		gnubuckets = get_dynamic_data (file, ngnubuckets, 4);

		if (gnubuckets == NULL)
			goto no_gnu_hash;

		for (i = 0; i < ngnubuckets; i++)
			if (gnubuckets[i] != 0)
			{
				if (gnubuckets[i] < gnusymidx)
					return 0;

				if (maxchain == 0xffffffff || gnubuckets[i] > maxchain)
					maxchain = gnubuckets[i];
			}

		if (maxchain == 0xffffffff)
			goto no_gnu_hash;

		maxchain -= gnusymidx;

		if (fseek (file,
				   (archive_file_offset
					+ offset_from_vma (file, buckets_vma
									   + 4 * (ngnubuckets + maxchain), 4)),
				   SEEK_SET))
		{
			printf (("Unable to seek to start of dynamic information\n"));
			goto no_gnu_hash;
		}

		do
		{
			if (fread (nb, 4, 1, file) != 1)
			{
				printf (("Failed to determine last chain length\n"));
				goto no_gnu_hash;
			}

			if (maxchain + 1 == 0)
				goto no_gnu_hash;

			++maxchain;
		}
		while ((byte_get (nb, 4) & 1) == 0);

		if (fseek (file,
				   (archive_file_offset
					+ offset_from_vma (file, buckets_vma + 4 * ngnubuckets, 4)),
				   SEEK_SET))
		{
			printf (("Unable to seek to start of dynamic information\n"));
			goto no_gnu_hash;
		}

		gnuchains = get_dynamic_data (file, maxchain, 4);

no_gnu_hash:
		if (gnuchains == NULL)
		{
			free (gnubuckets);
			gnubuckets = NULL;
			ngnubuckets = 0;
			if (do_using_dynamic)
				return 0;
		}
	}

	if ((dynamic_info[DT_HASH] || dynamic_info_DT_GNU_HASH)
			&& do_syms
			&& do_using_dynamic
			&& dynamic_strings != NULL)
	{
		unsigned long hn;

		if (dynamic_info[DT_HASH])
		{
			bfd_vma si;

			printf (("\nSymbol table for image:\n"));
			if (is_32bit_elf)
				printf (("  Num Buc:    Value  Size   Type   Bind Vis      Ndx Name\n"));
			else
				printf (("  Num Buc:    Value          Size   Type   Bind Vis      Ndx Name\n"));

			for (hn = 0; hn < nbuckets; hn++)
			{
				if (! buckets[hn])
					continue;

				for (si = buckets[hn]; si < nchains && si > 0; si = chains[si])
					print_dynamic_symbol (si, hn);
			}
		}

		if (dynamic_info_DT_GNU_HASH)
		{
			printf (("\nSymbol table of `.gnu.hash' for image:\n"));
			if (is_32bit_elf)
				printf (("  Num Buc:    Value  Size   Type   Bind Vis      Ndx Name\n"));
			else
				printf (("  Num Buc:    Value          Size   Type   Bind Vis      Ndx Name\n"));

			for (hn = 0; hn < ngnubuckets; ++hn)
				if (gnubuckets[hn] != 0)
				{
					bfd_vma si = gnubuckets[hn];
					bfd_vma off = si - gnusymidx;

					do
					{
						print_dynamic_symbol (si, hn);
						si++;
					}
					while ((gnuchains[off++] & 1) == 0);
				}
		}
	}
	else if (do_dyn_syms || (do_syms && !do_using_dynamic))
	{
		unsigned int i;

		for (i = 0, section = section_headers;
				i < elf_header.e_shnum;
				i++, section++)
		{
			unsigned int si;
			char * strtab = NULL;
			unsigned long int strtab_size = 0;
			Elf_Internal_Sym * symtab;
			Elf_Internal_Sym * psym;
			unsigned long num_syms;

			if ((section->sh_type != SHT_SYMTAB
					&& section->sh_type != SHT_DYNSYM)
					|| (!do_syms
						&& section->sh_type == SHT_SYMTAB))
				continue;

			if (section->sh_entsize == 0)
			{
				printf (("\nSymbol table '%s' has a sh_entsize of zero!\n"),
						SECTION_NAME (section));
				continue;
			}

			printf (("\nSymbol table '%s' contains %lu entries:\n"),
					SECTION_NAME (section),
					(unsigned long) (section->sh_size / section->sh_entsize));

			if (is_32bit_elf)
				printf (("   Num:    Value  Size Type    Bind   Vis      Ndx Name\n"));
			else
				printf (("   Num:    Value          Size Type    Bind   Vis      Ndx Name\n"));

			symtab = get_elf_symbols (file, section, & num_syms);
			if (symtab == NULL)
				continue;

			if (section->sh_link == elf_header.e_shstrndx)
			{
				strtab = string_table;
				strtab_size = string_table_length;
			}
			else if (section->sh_link < elf_header.e_shnum)
			{
				Elf_Internal_Shdr * string_sec;

				string_sec = section_headers + section->sh_link;

				strtab = (char *) get_data (NULL, file, string_sec->sh_offset,
											1, string_sec->sh_size,
											("string table"));
				strtab_size = strtab != NULL ? string_sec->sh_size : 0;
			}
#if 0
			for (si = 0, psym = symtab; si < num_syms; si++, psym++)
			{
				printf ("%6d: ", si);
				print_vma (psym->st_value, LONG_HEX);
				putchar (' ');
				print_vma (psym->st_size, DEC_5);
				printf (" %-7s", get_symbol_type (ELF_ST_TYPE (psym->st_info)));
				printf (" %-6s", get_symbol_binding (ELF_ST_BIND (psym->st_info)));
				printf (" %-7s", get_symbol_visibility (ELF_ST_VISIBILITY (psym->st_other)));
				/* Check to see if any other bits in the st_other field are set.
				   Note - displaying this information disrupts the layout of the
				   table being generated, but for the moment this case is very rare.  */
				if (psym->st_other ^ ELF_ST_VISIBILITY (psym->st_other))
					printf (" [%s] ", get_symbol_other (psym->st_other ^ ELF_ST_VISIBILITY (psym->st_other)));
				printf (" %4s ", get_symbol_index_type (psym->st_shndx));
				print_symbol (25, psym->st_name < strtab_size
							  ? strtab + psym->st_name : ("<corrupt>"));

				if (section->sh_type == SHT_DYNSYM
						&& version_info[DT_VERSIONTAGIDX (DT_VERSYM)] != 0)
				{
					unsigned char data[2];
					unsigned short vers_data;
					unsigned long offset;
					int is_nobits;
					int check_def;

					offset = offset_from_vma
							 (file, version_info[DT_VERSIONTAGIDX (DT_VERSYM)],
							  sizeof data + si * sizeof (vers_data));

					if (get_data (&data, file, offset + si * sizeof (vers_data),
								  sizeof (data), 1, ("version data")) == NULL)
						break;

					vers_data = byte_get (data, 2);

					is_nobits = (psym->st_shndx < elf_header.e_shnum
								 && section_headers[psym->st_shndx].sh_type
								 == SHT_NOBITS);

					check_def = (psym->st_shndx != SHN_UNDEF);

					if ((vers_data & VERSYM_HIDDEN) || vers_data > 1)
					{
						if (version_info[DT_VERSIONTAGIDX (DT_VERNEED)]
								&& (is_nobits || ! check_def))
						{
							Elf_External_Verneed evn;
							Elf_Internal_Verneed ivn;
							Elf_Internal_Vernaux ivna;

							/* We must test both.  */
							offset = offset_from_vma
									 (file, version_info[DT_VERSIONTAGIDX (DT_VERNEED)],
									  sizeof evn);

							do
							{
								unsigned long vna_off;

								if (get_data (&evn, file, offset, sizeof (evn), 1,
											  ("version need")) == NULL)
								{
									ivna.vna_next = 0;
									ivna.vna_other = 0;
									ivna.vna_name = 0;
									break;
								}

								ivn.vn_aux  = BYTE_GET (evn.vn_aux);
								ivn.vn_next = BYTE_GET (evn.vn_next);

								vna_off = offset + ivn.vn_aux;

								do
								{
									Elf_External_Vernaux evna;

									if (get_data (&evna, file, vna_off,
												  sizeof (evna), 1,
												  ("version need aux (3)")) == NULL)
									{
										ivna.vna_next = 0;
										ivna.vna_other = 0;
										ivna.vna_name = 0;
									}
									else
									{
										ivna.vna_other = BYTE_GET (evna.vna_other);
										ivna.vna_next  = BYTE_GET (evna.vna_next);
										ivna.vna_name  = BYTE_GET (evna.vna_name);
									}

									vna_off += ivna.vna_next;
								}
								while (ivna.vna_other != vers_data
										&& ivna.vna_next != 0);

								if (ivna.vna_other == vers_data)
									break;

								offset += ivn.vn_next;
							}
							while (ivn.vn_next != 0);

							if (ivna.vna_other == vers_data)
							{
								printf ("@%s (%d)",
										ivna.vna_name < strtab_size
										? strtab + ivna.vna_name : ("<corrupt>"),
										ivna.vna_other);
								check_def = 0;
							}
							else if (! is_nobits)
								printf (("bad dynamic symbol\n"));
							else
								check_def = 1;
						}

						if (check_def)
						{
							if (vers_data != 0x8001
									&& version_info[DT_VERSIONTAGIDX (DT_VERDEF)])
							{
								Elf_Internal_Verdef ivd;
								Elf_Internal_Verdaux ivda;
								Elf_External_Verdaux evda;
								unsigned long off;

								off = offset_from_vma
									  (file,
									   version_info[DT_VERSIONTAGIDX (DT_VERDEF)],
									   sizeof (Elf_External_Verdef));

								do
								{
									Elf_External_Verdef evd;

									if (get_data (&evd, file, off, sizeof (evd),
												  1, ("version def")) == NULL)
									{
										ivd.vd_ndx = 0;
										ivd.vd_aux = 0;
										ivd.vd_next = 0;
									}
									else
									{
										ivd.vd_ndx = BYTE_GET (evd.vd_ndx);
										ivd.vd_aux = BYTE_GET (evd.vd_aux);
										ivd.vd_next = BYTE_GET (evd.vd_next);
									}

									off += ivd.vd_next;
								}
								while (ivd.vd_ndx != (vers_data & VERSYM_VERSION)
										&& ivd.vd_next != 0);

								off -= ivd.vd_next;
								off += ivd.vd_aux;

								if (get_data (&evda, file, off, sizeof (evda),
											  1, ("version def aux")) == NULL)
									break;

								ivda.vda_name = BYTE_GET (evda.vda_name);

								if (psym->st_name != ivda.vda_name)
									printf ((vers_data & VERSYM_HIDDEN)
											? "@%s" : "@@%s",
											ivda.vda_name < strtab_size
											? strtab + ivda.vda_name : ("<corrupt>"));
							}
						}
					}
				}

				putchar ('\n');
			}
#endif
			free (symtab);
			if (strtab != string_table)
				free (strtab);
		}
	}
	else if (do_syms)
		printf
		(("\nDynamic symbol information is not available for displaying symbols.\n"));

	return 1;
}

#if 0
/* Check to see if the given reloc needs to be handled in a target specific
   manner.  If so then process the reloc and return TRUE otherwise return
   FALSE.  */

static bfd_boolean
target_specific_reloc_handling (Elf_Internal_Rela * reloc,
								unsigned char *     start,
								Elf_Internal_Sym *  symtab)
{
	unsigned int reloc_type = get_reloc_type (reloc->r_info);

	switch (elf_header.e_machine)
	{
	case EM_MN10300:
	case EM_CYGNUS_MN10300:
	{
		static Elf_Internal_Sym * saved_sym = NULL;

		switch (reloc_type)
		{
		case 34: /* R_MN10300_ALIGN */
			return TRUE;
		case 33: /* R_MN10300_SYM_DIFF */
			saved_sym = symtab + get_reloc_symindex (reloc->r_info);
			return TRUE;
		case 1: /* R_MN10300_32 */
		case 2: /* R_MN10300_16 */
			if (saved_sym != NULL)
			{
				bfd_vma value;

				value = reloc->r_addend
						+ (symtab[get_reloc_symindex (reloc->r_info)].st_value
						   - saved_sym->st_value);

				byte_put (start + reloc->r_offset, value, reloc_type == 1 ? 4 : 2);

				saved_sym = NULL;
				return TRUE;
			}
			break;
		default:
			if (saved_sym != NULL)
				printf (("Unhandled MN10300 reloc type found after SYM_DIFF reloc"));
			break;
		}
		break;
	}
	}

	return FALSE;
}

/* Returns TRUE iff RELOC_TYPE is a 32-bit absolute RELA relocation used in
   DWARF debug sections.  This is a target specific test.  Note - we do not
   go through the whole including-target-headers-multiple-times route, (as
   we have already done with <elf/h8.h>) because this would become very
   messy and even then this function would have to contain target specific
   information (the names of the relocs instead of their numeric values).
   FIXME: This is not the correct way to solve this problem.  The proper way
   is to have target specific reloc sizing and typing functions created by
   the reloc-macros.h header, in the same way that it already creates the
   reloc naming functions.  */

static bfd_boolean
is_32bit_abs_reloc (unsigned int reloc_type)
{
	switch (elf_header.e_machine)
	{
	case EM_386:
		return reloc_type == 1; /* R_386_32.  */
	case EM_ARM:
		return reloc_type == 2; /* R_ARM_ABS32 */
	case EM_X86_64:
		return reloc_type == 10; /* R_X86_64_32.  */
	default:
		printf (("Missing knowledge of 32-bit reloc types used in DWARF sections of machine number %d\n"),
			   elf_header.e_machine);
		abort ();
	}
}

/* Like is_32bit_abs_reloc except that it returns TRUE iff RELOC_TYPE is
   a 32-bit pc-relative RELA relocation used in DWARF debug sections.  */

static bfd_boolean
is_32bit_pcrel_reloc (unsigned int reloc_type)
{
	switch (elf_header.e_machine)
	{
	case EM_386:
		return reloc_type == 2;  /* R_386_PC32.  */
	case EM_ARM:
		return reloc_type == 3;  /* R_ARM_REL32 */
	case EM_X86_64:
		return reloc_type == 2;  /* R_X86_64_PC32.  */
	default:
		/* Do not abort or issue an error message here.  Not all targets use
		pc-relative 32-bit relocs in their DWARF debug information and we
		 have already tested for target coverage in is_32bit_abs_reloc.  A
		 more helpful warning message will be generated by apply_relocations
		 anyway, so just return.  */
		return FALSE;
	}
}

/* Like is_32bit_abs_reloc except that it returns TRUE iff RELOC_TYPE is
   a 64-bit absolute RELA relocation used in DWARF debug sections.  */

static bfd_boolean
is_64bit_abs_reloc (unsigned int reloc_type)
{
	switch (elf_header.e_machine)
	{
	case EM_AARCH64:
		return reloc_type == 257;	/* R_AARCH64_ABS64.  */
	case EM_ALPHA:
		return reloc_type == 2; /* R_ALPHA_REFQUAD.  */
	case EM_IA_64:
		return reloc_type == 0x27; /* R_IA64_DIR64LSB.  */
	case EM_PARISC:
		return reloc_type == 80; /* R_PARISC_DIR64.  */
	case EM_PPC64:
		return reloc_type == 38; /* R_PPC64_ADDR64.  */
	case EM_SPARC32PLUS:
	case EM_SPARCV9:
	case EM_SPARC:
		return reloc_type == 54; /* R_SPARC_UA64.  */
	case EM_X86_64:
	case EM_L1OM:
	case EM_K1OM:
		return reloc_type == 1; /* R_X86_64_64.  */
	case EM_S390_OLD:
	case EM_S390:
		return reloc_type == 22;	/* R_S390_64.  */
	case EM_TILEGX:
		return reloc_type == 1; /* R_TILEGX_64.  */
	case EM_MIPS:
		return reloc_type == 18;	/* R_MIPS_64.  */
	default:
		return FALSE;
	}
}

/* Like is_32bit_pcrel_reloc except that it returns TRUE iff RELOC_TYPE is
   a 64-bit pc-relative RELA relocation used in DWARF debug sections.  */

static bfd_boolean
is_64bit_pcrel_reloc (unsigned int reloc_type)
{
	switch (elf_header.e_machine)
	{
	case EM_AARCH64:
		return reloc_type == 260;	/* R_AARCH64_PREL64.  */
	case EM_ALPHA:
		return reloc_type == 11; /* R_ALPHA_SREL64.  */
	case EM_IA_64:
		return reloc_type == 0x4f; /* R_IA64_PCREL64LSB.  */
	case EM_PARISC:
		return reloc_type == 72; /* R_PARISC_PCREL64.  */
	case EM_PPC64:
		return reloc_type == 44; /* R_PPC64_REL64.  */
	case EM_SPARC32PLUS:
	case EM_SPARCV9:
	case EM_SPARC:
		return reloc_type == 46; /* R_SPARC_DISP64.  */
	case EM_X86_64:
	case EM_L1OM:
	case EM_K1OM:
		return reloc_type == 24; /* R_X86_64_PC64.  */
	case EM_S390_OLD:
	case EM_S390:
		return reloc_type == 23;	/* R_S390_PC64.  */
	case EM_TILEGX:
		return reloc_type == 5;  /* R_TILEGX_64_PCREL.  */
	default:
		return FALSE;
	}
}

/* Like is_32bit_abs_reloc except that it returns TRUE iff RELOC_TYPE is
   a 24-bit absolute RELA relocation used in DWARF debug sections.  */

static bfd_boolean
is_24bit_abs_reloc (unsigned int reloc_type)
{
	switch (elf_header.e_machine)
	{
	case EM_CYGNUS_MN10200:
	case EM_MN10200:
		return reloc_type == 4; /* R_MN10200_24.  */
	default:
		return FALSE;
	}
}

/* Like is_32bit_abs_reloc except that it returns TRUE iff RELOC_TYPE is
   a 16-bit absolute RELA relocation used in DWARF debug sections.  */

static bfd_boolean
is_16bit_abs_reloc (unsigned int reloc_type)
{
	switch (elf_header.e_machine)
	{
	case EM_AVR_OLD:
	case EM_AVR:
		return reloc_type == 4; /* R_AVR_16.  */
	case EM_ADAPTEVA_EPIPHANY:
		return reloc_type == 5;
	case EM_CYGNUS_D10V:
	case EM_D10V:
		return reloc_type == 3; /* R_D10V_16.  */
	case EM_H8S:
	case EM_H8_300:
	case EM_H8_300H:
		return reloc_type == R_H8_DIR16;
	case EM_IP2K_OLD:
	case EM_IP2K:
		return reloc_type == 1; /* R_IP2K_16.  */
	case EM_M32C_OLD:
	case EM_M32C:
		return reloc_type == 1; /* R_M32C_16 */
	case EM_MSP430_OLD:
	case EM_MSP430:
		return reloc_type == 5; /* R_MSP430_16_BYTE.  */
	case EM_ALTERA_NIOS2:
	case EM_NIOS32:
		return reloc_type == 9; /* R_NIOS_16.  */
	case EM_TI_C6000:
		return reloc_type == 2; /* R_C6000_ABS16.  */
	case EM_XC16X:
	case EM_C166:
		return reloc_type == 2; /* R_XC16C_ABS_16.  */
	case EM_CYGNUS_MN10200:
	case EM_MN10200:
		return reloc_type == 2; /* R_MN10200_16.  */
	case EM_CYGNUS_MN10300:
	case EM_MN10300:
		return reloc_type == 2; /* R_MN10300_16.  */
	case EM_XGATE:
		return reloc_type == 3; /* R_XGATE_16.  */
	default:
		return FALSE;
	}
}

/* Returns TRUE iff RELOC_TYPE is a NONE relocation used for discarded
   relocation entries (possibly formerly used for SHT_GROUP sections).  */

static bfd_boolean
is_none_reloc (unsigned int reloc_type)
{
	switch (elf_header.e_machine)
	{
	case EM_68K:     /* R_68K_NONE.  */
	case EM_386:     /* R_386_NONE.  */
	case EM_SPARC32PLUS:
	case EM_SPARCV9:
	case EM_SPARC:   /* R_SPARC_NONE.  */
	case EM_MIPS:    /* R_MIPS_NONE.  */
	case EM_PARISC:  /* R_PARISC_NONE.  */
	case EM_ALPHA:   /* R_ALPHA_NONE.  */
	case EM_ADAPTEVA_EPIPHANY:
	case EM_PPC:     /* R_PPC_NONE.  */
	case EM_PPC64:   /* R_PPC64_NONE.  */
	case EM_ARM:     /* R_ARM_NONE.  */
	case EM_IA_64:   /* R_IA64_NONE.  */
	case EM_SH:      /* R_SH_NONE.  */
	case EM_S390_OLD:
	case EM_S390:    /* R_390_NONE.  */
	case EM_CRIS:    /* R_CRIS_NONE.  */
	case EM_X86_64:  /* R_X86_64_NONE.  */
	case EM_L1OM:    /* R_X86_64_NONE.  */
	case EM_K1OM:    /* R_X86_64_NONE.  */
	case EM_MN10300: /* R_MN10300_NONE.  */
	case EM_MOXIE:   /* R_MOXIE_NONE.  */
	case EM_M32R:    /* R_M32R_NONE.  */
	case EM_TI_C6000:/* R_C6000_NONE.  */
	case EM_TILEGX:  /* R_TILEGX_NONE.  */
	case EM_TILEPRO: /* R_TILEPRO_NONE.  */
	case EM_XC16X:
	case EM_C166:    /* R_XC16X_NONE.  */
		return reloc_type == 0;
	case EM_AARCH64:
		return reloc_type == 0 || reloc_type == 256;
	case EM_XTENSA_OLD:
	case EM_XTENSA:
		return (reloc_type == 0      /* R_XTENSA_NONE.  */
				|| reloc_type == 17  /* R_XTENSA_DIFF8.  */
				|| reloc_type == 18  /* R_XTENSA_DIFF16.  */
				|| reloc_type == 19  /* R_XTENSA_DIFF32.  */);
	}
	return FALSE;
}

/* Apply relocations to a section.
   Note: So far support has been added only for those relocations
   which can be found in debug sections.
   FIXME: Add support for more relocations ?  */

static void
apply_relocations (void * file,
				   Elf_Internal_Shdr * section,
				   unsigned char * start)
{
	Elf_Internal_Shdr * relsec;
	unsigned char * end = start + section->sh_size;

	if (elf_header.e_type != ET_REL)
		return;

	/* Find the reloc section associated with the section.  */
	for (relsec = section_headers;
			relsec < section_headers + elf_header.e_shnum;
			++relsec)
	{
		bfd_boolean is_rela;
		unsigned long num_relocs;
		Elf_Internal_Rela * relocs;
		Elf_Internal_Rela * rp;
		Elf_Internal_Shdr * symsec;
		Elf_Internal_Sym * symtab;
		unsigned long num_syms;
		Elf_Internal_Sym * sym;

		if ((relsec->sh_type != SHT_RELA && relsec->sh_type != SHT_REL)
				|| relsec->sh_info >= elf_header.e_shnum
				|| section_headers + relsec->sh_info != section
				|| relsec->sh_size == 0
				|| relsec->sh_link >= elf_header.e_shnum)
			continue;

		is_rela = relsec->sh_type == SHT_RELA;

		if (is_rela)
		{
			if (!slurp_rela_relocs ((FILE *) file, relsec->sh_offset,
									relsec->sh_size, & relocs, & num_relocs))
				return;
		}
		else
		{
			if (!slurp_rel_relocs ((FILE *) file, relsec->sh_offset,
								   relsec->sh_size, & relocs, & num_relocs))
				return;
		}

		/* SH uses RELA but uses in place value instead of the addend field.  */
		if (elf_header.e_machine == EM_SH)
			is_rela = FALSE;

		symsec = section_headers + relsec->sh_link;
		symtab = get_elf_symbols ((FILE *) file, symsec, & num_syms);

		for (rp = relocs; rp < relocs + num_relocs; ++rp)
		{
			bfd_vma         addend;
			unsigned int    reloc_type;
			unsigned int    reloc_size;
			unsigned char * rloc;
			unsigned long   sym_index;

			reloc_type = get_reloc_type (rp->r_info);

			if (target_specific_reloc_handling (rp, start, symtab))
				continue;
			else if (is_none_reloc (reloc_type))
				continue;
			else if (is_32bit_abs_reloc (reloc_type)
					 || is_32bit_pcrel_reloc (reloc_type))
				reloc_size = 4;
			else if (is_64bit_abs_reloc (reloc_type)
					 || is_64bit_pcrel_reloc (reloc_type))
				reloc_size = 8;
			else if (is_24bit_abs_reloc (reloc_type))
				reloc_size = 3;
			else if (is_16bit_abs_reloc (reloc_type))
				reloc_size = 2;
			else
			{
				warn (("unable to apply unsupported reloc type %d to section %s\n"),
					  reloc_type, SECTION_NAME (section));
				continue;
			}

			rloc = start + rp->r_offset;
			if ((rloc + reloc_size) > end)
			{
				warn (("skipping invalid relocation offset 0x%lx in section %s\n"),
					  (unsigned long) rp->r_offset,
					  SECTION_NAME (section));
				continue;
			}

			sym_index = (unsigned long) get_reloc_symindex (rp->r_info);
			if (sym_index >= num_syms)
			{
				warn (("skipping invalid relocation symbol index 0x%lx in section %s\n"),
					  sym_index, SECTION_NAME (section));
				continue;
			}
			sym = symtab + sym_index;

			/* If the reloc has a symbol associated with it,
			   make sure that it is of an appropriate type.

			   Relocations against symbols without type can happen.
			   Gcc -feliminate-dwarf2-dups may generate symbols
			   without type for debug info.

			   Icc generates relocations against function symbols
			   instead of local labels.

			   Relocations against object symbols can happen, eg when
			   referencing a global array.  For an example of this see
			   the _clz.o binary in libgcc.a.  */
			if (sym != symtab
					&& ELF_ST_TYPE (sym->st_info) > STT_SECTION)
			{
				warn (("skipping unexpected symbol type %s in %ld'th relocation in section %s\n"),
					  get_symbol_type (ELF_ST_TYPE (sym->st_info)),
					  (long int)(rp - relocs),
					  SECTION_NAME (relsec));
				continue;
			}

			addend = 0;
			if (is_rela)
				addend += rp->r_addend;
			/* R_XTENSA_32, R_PJ_DATA_DIR32 and R_D30V_32_NORMAL are
			   partial_inplace.  */
			if (!is_rela
					|| (elf_header.e_machine == EM_XTENSA
						&& reloc_type == 1)
					|| ((elf_header.e_machine == EM_PJ
						 || elf_header.e_machine == EM_PJ_OLD)
						&& reloc_type == 1)
					|| ((elf_header.e_machine == EM_D30V
						 || elf_header.e_machine == EM_CYGNUS_D30V)
						&& reloc_type == 12))
				addend += byte_get (rloc, reloc_size);

			if (is_32bit_pcrel_reloc (reloc_type)
					|| is_64bit_pcrel_reloc (reloc_type))
			{
				/* On HPPA, all pc-relative relocations are biased by 8.  */
				if (elf_header.e_machine == EM_PARISC)
					addend -= 8;
				byte_put (rloc, (addend + sym->st_value) - rp->r_offset,
						  reloc_size);
			}
			else
				byte_put (rloc, addend + sym->st_value, reloc_size);
		}

		free (symtab);
		free (relocs);
		break;
	}
}

#ifdef SUPPORT_DISASSEMBLY
static int
disassemble_section (Elf_Internal_Shdr * section, FILE * file)
{
	printf (("\nAssembly dump of section %s\n"),
			SECTION_NAME (section));

	/* XXX -- to be done --- XXX */

	return 1;
}
#endif

/* Reads in the contents of SECTION from FILE, returning a pointer
   to a malloc'ed buffer or NULL if something went wrong.  */

static char *
get_section_contents (Elf_Internal_Shdr * section, FILE * file)
{
	bfd_size_type num_bytes;

	num_bytes = section->sh_size;

	if (num_bytes == 0 || section->sh_type == SHT_NOBITS)
	{
		printf (("\nSection '%s' has no data to dump.\n"),
				SECTION_NAME (section));
		return NULL;
	}

	return  (char *) get_data (NULL, file, section->sh_offset, 1, num_bytes,
							   ("section contents"));
}


static void
dump_section_as_strings (Elf_Internal_Shdr * section, FILE * file)
{
	Elf_Internal_Shdr * relsec;
	bfd_size_type num_bytes;
	char * data;
	char * end;
	char * start;
	char * name = SECTION_NAME (section);
	bfd_boolean some_strings_shown;

	start = get_section_contents (section, file);
	if (start == NULL)
		return;

	printf (("\nString dump of section '%s':\n"), name);

	/* If the section being dumped has relocations against it the user might
	   be expecting these relocations to have been applied.  Check for this
	   case and issue a warning message in order to avoid confusion.
	   FIXME: Maybe we ought to have an option that dumps a section with
	   relocs applied ?  */
	for (relsec = section_headers;
			relsec < section_headers + elf_header.e_shnum;
			++relsec)
	{
		if ((relsec->sh_type != SHT_RELA && relsec->sh_type != SHT_REL)
				|| relsec->sh_info >= elf_header.e_shnum
				|| section_headers + relsec->sh_info != section
				|| relsec->sh_size == 0
				|| relsec->sh_link >= elf_header.e_shnum)
			continue;

		printf (("  Note: This section has relocations against it, but these have NOT been applied to this dump.\n"));
		break;
	}

	num_bytes = section->sh_size;
	data = start;
	end  = start + num_bytes;
	some_strings_shown = FALSE;

	while (data < end)
	{
		while (!ISPRINT (* data))
			if (++ data >= end)
				break;

		if (data < end)
		{
#ifndef __MSVCRT__
			/* PR 11128: Use two separate invocations in order to work
			       around bugs in the Solaris 8 implementation of printf.  */
			printf ("  [%6tx]  ", data - start);
			printf ("%s\n", data);
#else
			printf ("  [%6Ix]  %s\n", (size_t) (data - start), data);
#endif
			data += strlen (data);
			some_strings_shown = TRUE;
		}
	}

	if (! some_strings_shown)
		printf (("  No strings found in this section."));

	free (start);

	putchar ('\n');
}

static void
dump_section_as_bytes (Elf_Internal_Shdr * section,
					   FILE * file,
					   bfd_boolean relocate)
{
	Elf_Internal_Shdr * relsec;
	bfd_size_type bytes;
	bfd_vma addr;
	unsigned char * data;
	unsigned char * start;

	start = (unsigned char *) get_section_contents (section, file);
	if (start == NULL)
		return;

	printf (("\nHex dump of section '%s':\n"), SECTION_NAME (section));

	if (relocate)
	{
		apply_relocations (file, section, start);
	}
	else
	{
		/* If the section being dumped has relocations against it the user might
		be expecting these relocations to have been applied.  Check for this
		 case and issue a warning message in order to avoid confusion.
		 FIXME: Maybe we ought to have an option that dumps a section with
		 relocs applied ?  */
		for (relsec = section_headers;
				relsec < section_headers + elf_header.e_shnum;
				++relsec)
		{
			if ((relsec->sh_type != SHT_RELA && relsec->sh_type != SHT_REL)
					|| relsec->sh_info >= elf_header.e_shnum
					|| section_headers + relsec->sh_info != section
					|| relsec->sh_size == 0
					|| relsec->sh_link >= elf_header.e_shnum)
				continue;

			printf ((" NOTE: This section has relocations against it, but these have NOT been applied to this dump.\n"));
			break;
		}
	}

	addr = section->sh_addr;
	bytes = section->sh_size;
	data = start;

	while (bytes)
	{
		int j;
		int k;
		int lbytes;

		lbytes = (bytes > 16 ? 16 : bytes);

		printf ("  0x%8.8lx ", (unsigned long) addr);

		for (j = 0; j < 16; j++)
		{
			if (j < lbytes)
				printf ("%2.2x", data[j]);
			else
				printf ("  ");

			if ((j & 3) == 3)
				printf (" ");
		}

		for (j = 0; j < lbytes; j++)
		{
			k = data[j];
			if (k >= ' ' && k < 0x7f)
				printf ("%c", k);
			else
				printf (".");
		}

		putchar ('\n');

		data  += lbytes;
		addr  += lbytes;
		bytes -= lbytes;
	}

	free (start);

	putchar ('\n');
}

/* Uncompresses a section that was compressed using zlib, in place.  */

static int
uncompress_section_contents (unsigned char **buffer ATTRIBUTE_UNUSED,
							 dwarf_size_type *size ATTRIBUTE_UNUSED)
{
#ifndef HAVE_ZLIB_H
	return FALSE;
#else
	dwarf_size_type compressed_size = *size;
	unsigned char * compressed_buffer = *buffer;
	dwarf_size_type uncompressed_size;
	unsigned char * uncompressed_buffer;
	z_stream strm;
	int rc;
	dwarf_size_type header_size = 12;

	/* Read the zlib header.  In this case, it should be "ZLIB" followed
	   by the uncompressed section size, 8 bytes in big-endian order.  */
	if (compressed_size < header_size
			|| ! streq ((char *) compressed_buffer, "ZLIB"))
		return 0;

	uncompressed_size = compressed_buffer[4];
	uncompressed_size <<= 8;
	uncompressed_size += compressed_buffer[5];
	uncompressed_size <<= 8;
	uncompressed_size += compressed_buffer[6];
	uncompressed_size <<= 8;
	uncompressed_size += compressed_buffer[7];
	uncompressed_size <<= 8;
	uncompressed_size += compressed_buffer[8];
	uncompressed_size <<= 8;
	uncompressed_size += compressed_buffer[9];
	uncompressed_size <<= 8;
	uncompressed_size += compressed_buffer[10];
	uncompressed_size <<= 8;
	uncompressed_size += compressed_buffer[11];

	/* It is possible the section consists of several compressed
	   buffers concatenated together, so we uncompress in a loop.  */
	strm.zalloc = NULL;
	strm.zfree = NULL;
	strm.opaque = NULL;
	strm.avail_in = compressed_size - header_size;
	strm.next_in = (Bytef *) compressed_buffer + header_size;
	strm.avail_out = uncompressed_size;
	uncompressed_buffer = (unsigned char *) xmalloc (uncompressed_size);

	rc = inflateInit (& strm);
	while (strm.avail_in > 0)
	{
		if (rc != Z_OK)
			goto fail;
		strm.next_out = ((Bytef *) uncompressed_buffer
						 + (uncompressed_size - strm.avail_out));
		rc = inflate (&strm, Z_FINISH);
		if (rc != Z_STREAM_END)
			goto fail;
		rc = inflateReset (& strm);
	}
	rc = inflateEnd (& strm);
	if (rc != Z_OK
			|| strm.avail_out != 0)
		goto fail;

	free (compressed_buffer);
	*buffer = uncompressed_buffer;
	*size = uncompressed_size;
	return 1;

fail:
	free (uncompressed_buffer);
	/* Indicate decompression failure.  */
	*buffer = NULL;
	return 0;
#endif  /* HAVE_ZLIB_H */
}


#endif

static int
get_file_header (FILE * file)
{
	/* Read in the identity array.  */
	if (fread (elf_header.e_ident, EI_NIDENT, 1, file) != 1)
		return 0;

	/* Determine how to read the rest of the header.  */
	switch (elf_header.e_ident[EI_DATA])
	{
	default: /* fall through */
	case ELFDATANONE: /* fall through */
	case ELFDATA2LSB:
		byte_get = byte_get_little_endian;
		byte_put = byte_put_little_endian;
		break;
	case ELFDATA2MSB:
		byte_get = byte_get_big_endian;
		byte_put = byte_put_big_endian;
		break;
	}

	// this is interesting since we get a 64-bit elf file from a 32-bit system
#if TARGET_LONG_BITS == 64
	if (elf_header.e_ident[EI_CLASS] != ELFCLASS64) {
		// 
		return 0;
	}
#else
	if (elf_header.e_ident[EI_CLASS] == ELFCLASS64) {
		return 0;
	}
#endif

	/* Read in the rest of the header.  */
	Elf_External_Ehdr ehdr;

	if (fread (ehdr.e_type, sizeof (ehdr) - EI_NIDENT, 1, file) != 1)
		return 0;

	elf_header.e_type      = BYTE_GET (ehdr.e_type);
	elf_header.e_machine   = BYTE_GET (ehdr.e_machine);
	elf_header.e_version   = BYTE_GET (ehdr.e_version);
	elf_header.e_entry     = BYTE_GET (ehdr.e_entry);
	elf_header.e_phoff     = BYTE_GET (ehdr.e_phoff);
	elf_header.e_shoff     = BYTE_GET (ehdr.e_shoff);
	elf_header.e_flags     = BYTE_GET (ehdr.e_flags);
	elf_header.e_ehsize    = BYTE_GET (ehdr.e_ehsize);
	elf_header.e_phentsize = BYTE_GET (ehdr.e_phentsize);
	elf_header.e_phnum     = BYTE_GET (ehdr.e_phnum);
	elf_header.e_shentsize = BYTE_GET (ehdr.e_shentsize);
	elf_header.e_shnum     = BYTE_GET (ehdr.e_shnum);
	elf_header.e_shstrndx  = BYTE_GET (ehdr.e_shstrndx);

	if (elf_header.e_shoff)
	{
		get_section_headers (file, 1);
	}

	return 1;
}

/* Process one ELF object file according to the command line options.
   This file may actually be stored in an archive.  The file is
   positioned at the start of the ELF object.  */

static int
process_object (char * file_name, FILE * file)
{
	unsigned int i;

	if (! get_file_header (file))
	{
		printf ("%s: Failed to read file header\n", file_name);
		return 1;
	}

	/* Initialise per file variables.  */
	for (i = ARRAY_SIZE (version_info); i--;)
		version_info[i] = 0;

	for (i = ARRAY_SIZE (dynamic_info); i--;)
		dynamic_info[i] = 0;
	dynamic_info_DT_GNU_HASH = 0;

	/* Process the file.  */
	printf (("\nFile: %s\n"), file_name);

#if 0
	/* Initialise the dump_sects array from the cmdline_dump_sects array.
	   Note we do this even if cmdline_dump_sects is empty because we
	   must make sure that the dump_sets array is zeroed out before each
	   object file is processed.  */
	if (num_dump_sects > num_cmdline_dump_sects)
		memset (dump_sects, 0, num_dump_sects * sizeof (* dump_sects));

	if (num_cmdline_dump_sects > 0)
	{
		if (num_dump_sects == 0)
			/* A sneaky way of allocating the dump_sects array.  */
			request_dump_bynumber (num_cmdline_dump_sects, 0);

		assert (num_dump_sects >= num_cmdline_dump_sects);
		memcpy (dump_sects, cmdline_dump_sects,
				num_cmdline_dump_sects * sizeof (* dump_sects));
	}

#endif
	if (! process_file_header ())
		return 1;

	if (! process_section_headers (file))
	{
		if (! do_using_dynamic)
			do_syms = do_dyn_syms = do_reloc = 0;
	}

	if (process_program_headers (file))
		process_dynamic_section (file);

	process_relocs (file);

	process_symbol_table (file);

	return 0;
}

static int
process_file (char * file_name)
{
	FILE * file;
	int ret;

	file = fopen (file_name, "rb");
	if (file == NULL)
	{
		printf ("Input file '%s' is not readable.\n", file_name);
		return 1;
	}


	rewind (file);
	archive_file_size = archive_file_offset = 0;
	ret = process_object (file_name, file);

	fclose (file);

	return ret;
}
/*
int
main (int argc, char ** argv)
{
	int err;

	process_file("/usr/lib/libical.so.0.48.0");

	return err;
}
*/

// is current memory section a valid ELF?
static bool is_valid_elf(CPUState *env, uint32_t cr3, target_ulong start_addr) {
	const char magicBytes[] = { 0x7f, 'E', 'L', 'F' };	// the magic bytes of ELF
	char chr[sizeof(magicBytes)];

	// read first 4 bytes, verify the magic bytes of ELF header
	return (
		!DECAF_read_mem_with_pgd(env, cr3, start_addr, sizeof(magicBytes), chr) &&
		!strncmp( magicBytes, chr, sizeof(magicBytes))
	);
}

int read_elf_info(CPUState *env, uint32_t cr3, target_ulong start_addr, uint64_t size) {
	if (!is_valid_elf(env, cr3, start_addr))
		return 0;

	//struct elfInfo elf_info;
	return 1;
}


