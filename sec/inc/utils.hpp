#pragma once
// #include <boost/compat/function_ref.hpp>
// #include <boost/core/bit.hpp>
#include <concepts>
#include <cstddef>
#include <limits>
#include <tuple>
#include <minitype.hpp>

//____________________________________________________________________________________________________________
// namespace std26
// {
// using boost::compat::function_ref;
// }
// //............................................................................................................
// namespace std23
// {
// using boost::core::byteswap;
// }
namespace stdxx
{
namespace impl
{
    template <typename T, typename... Ts, std::size_t... is>
    constexpr std::array<T, sizeof...(Ts)> to_array(const std::tuple<Ts...> &t, std::index_sequence<is...>)
    {
        return {std::get<is>(t)...};
    }
} // namespace impl

template <typename T, typename... Ts>
constexpr std::array<T, sizeof...(Ts)> to_array(const std::tuple<Ts...> &t)
{
    return impl::to_array<T>(t, std::make_index_sequence<sizeof...(Ts)>{});
}
} // namespace stdxx
//____________________________________________________________________________________________________________
template <typename T = void>
void NOT_IMPLEMENTED()
{
    static_assert(!std::is_same_v<T, T>);
}
//____________________________________________________________________________________________________________
template <typename T, auto v>
constexpr T safe_cast{v};
//............................................................................................................
#define lenof(type_or_expression) \
    safe_cast<unsigned, sizeof(type_or_expression)>
//............................................................................................................
#define numof(arr) \
    safe_cast<unsigned, sizeof(arr) / sizeof(arr[0])>
//____________________________________________________________________________________________________________
template <std::unsigned_integral T1, std::unsigned_integral T2>
constexpr T1 ceil_div(T1 dividend, T2 divisor)
{
    return static_cast<T1>(dividend == 0 ? 0 : (dividend - 1U) / divisor + 1);
}
//____________________________________________________________________________________________________________
template <auto n, typename T>
struct is_representable : std::false_type {};
//............................................................................................................
template <auto n, std::integral T>
    requires std::is_integral_v<decltype(n)>
             && (n < 0 ? (std::is_signed_v<T> && std::numeric_limits<T>::min() <= n)
                       : (n <= std::numeric_limits<T>::max()))
struct is_representable<n, T> : std::true_type {};
//............................................................................................................
template <auto n, typename T>
constexpr bool is_representable_v = is_representable<n, T>::value;
//____________________________________________________________________________________________________________
template <typename T>
struct is_tuple : std::false_type {};
//............................................................................................................
template <typename ... Ts>
struct is_tuple<std::tuple<Ts...>> : std::true_type {};
//............................................................................................................
template <typename T>
constexpr bool is_tuple_v = is_tuple<T>::value;
//............................................................................................................
template <typename T>
concept isTuple = is_tuple_v<T>;
//____________________________________________________________________________________________________________
constexpr u8 rotateByte(u8 v)
{
    const u8 rotateHalfByte[] = {
        0x00, 0x08, 0x04, 0x0C, 0x02, 0x0A, 0x06, 0x0E, 0x01, 0x09, 0x05, 0x0D, 0x03, 0x0B, 0x07, 0x0F
    };

    return (rotateHalfByte[v & 0x0F] << 4) | rotateHalfByte[(v >> 4) & 0x0F];
}
