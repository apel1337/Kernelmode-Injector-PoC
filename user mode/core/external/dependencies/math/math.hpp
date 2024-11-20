
namespace riot
{
	namespace math
	{
        template < typename _value_t >
            requires std::is_arithmetic_v< _value_t >
        using enough_float_t = std::conditional_t< sizeof( _value_t ) <= sizeof( float ) , float , double >;

        template < typename _ret_t >
            requires std::is_floating_point_v< _ret_t >
        inline constexpr auto k_pi = static_cast< _ret_t >( std::numbers::pi );

        template < typename _ret_t >
            requires std::is_floating_point_v< _ret_t >
        inline constexpr auto k_pi2 = static_cast< _ret_t >( k_pi< double > *2.0 );

        template < typename _ret_t >
            requires std::is_floating_point_v< _ret_t >
        inline constexpr auto k_rad_pi = static_cast< _ret_t >( 180.0 / k_pi< double > );

        template < typename _ret_t >
            requires std::is_floating_point_v< _ret_t >
        inline constexpr auto k_deg_pi = static_cast< _ret_t >( k_pi< double > / 180.0 );

        template < typename _value_t >
            requires std::is_arithmetic_v< _value_t >
        inline constexpr auto to_deg( const _value_t rad )
        {
            using ret_t = enough_float_t< _value_t >;

            return static_cast< ret_t >( rad * k_rad_pi< ret_t > );
        }

        template < typename _value_t >
            requires std::is_arithmetic_v< _value_t >
        inline constexpr auto to_rad( const _value_t deg )
        {
            using ret_t = enough_float_t< _value_t >;

            return static_cast< ret_t >( deg * k_deg_pi< ret_t > );
        }
	}
}