#ifndef PITH_BODY_SPARE_INCLUDED
#define PITH_BODY_SPARE_INCLUDED
typedef enum 
	{CharType, 
	 SizedText,
#ifdef SMIME
	 P7Type,
#endif
	 iCalType
} SpareType;

typedef struct body_sparep_t {
   SpareType sptype;
   void *data;
} BODY_SPARE_S;

void	   *create_body_sparep(SpareType, void *);
void	    free_body_sparep(void **);
void	   *get_body_sparep_data(void *);
SpareType   get_body_sparep_type(void *);


#endif /* PITH_BODY_SPARE_INCLUDED */
