using AutoMapper;
using LoginAndRegister.Ef_core;
using LoginAndRegister.Model;

namespace LoginAndRegister
{
    public class AutoMapper : Profile
    {
        public AutoMapper() { 
         CreateMap<RegisterModel , ApplicationUser>().ReverseMap();
        }
    }
}
