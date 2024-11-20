
namespace riot
{
	using namespace driver;

	namespace engine
	{
		template< class type >
		class tarray {
		public:
			tarray( ) : data( ) , count( ) , max_count( ) { }
			tarray( type* data , std::uint32_t count , std::uint32_t max_count ) :
				data( data ) , count( count ) , max_count( max_count ) { }

			type get( std::uintptr_t idx )
			{
				return m_vm->read< type >(
					reinterpret_cast< std::uintptr_t >( this->data ) + ( idx * sizeof( type ) )
				);
			}

			std::vector<type> get_itter( )
			{
				if ( this->count > this->max_count )
					return {};

				std::vector<type> buffer( this->count );

				m_vm->read_virtual(
					std::bit_cast< std::uintptr_t >( this->data ) ,
					buffer.data( ) ,
					sizeof( type ) * this->count
				);

				return buffer;
			}

			std::uintptr_t get_addr( )
			{
				return reinterpret_cast< std::uintptr_t >( this->data );
			}

			std::uint32_t size( ) const
			{
				return this->count;
			};

			std::uint32_t max_size( ) const
			{
				return this->max_count;
			};

			bool is_valid( ) const
			{
				return this->data != nullptr;
			};

			type* data;
			std::uint32_t count;
			std::uint32_t max_count;
		};

		class fvector 
		{
		public:
			fvector( ) : x( ) , y( ) , z( ) { }
			fvector( double x , double y , double z ) : x( x ) , y( y ) , z( z ) { }

			fvector operator + ( const fvector& other ) const { return { this->x + other.x, this->y + other.y, this->z + other.z }; }
			fvector operator - ( const fvector& other ) const { return { this->x - other.x, this->y - other.y, this->z - other.z }; }
			fvector operator * ( double offset ) const { return { this->x * offset, this->y * offset, this->z * offset }; }
			fvector operator / ( double offset ) const { return { this->x / offset, this->y / offset, this->z / offset }; }

			fvector& operator *= ( const double other ) { this->x *= other; this->y *= other; this->z *= other; return *this; }
			fvector& operator /= ( const double other ) { this->x /= other; this->y /= other; this->z /= other; return *this; }

			fvector& operator = ( const fvector& other ) { this->x = other.x; this->y = other.y; this->z = other.z; return *this; }
			fvector& operator += ( const fvector& other ) { this->x += other.x; this->y += other.y; this->z += other.z; return *this; }
			fvector& operator -= ( const fvector& other ) { this->x -= other.x; this->y -= other.y; this->z -= other.z; return *this; }
			fvector& operator *= ( const fvector& other ) { this->x *= other.x; this->y *= other.y; this->z *= other.z; return *this; }
			fvector& operator /= ( const fvector& other ) { this->x /= other.x; this->y /= other.y; this->z /= other.z; return *this; }

			operator bool( ) { return std::isfinite( this->x ) && std::isfinite( this->y ) && std::isfinite( this->z ); }
			friend bool operator == ( const fvector& a , const fvector& b ) { return a.x == b.x && a.y == b.y && a.z == b.z; }
			friend bool operator != ( const fvector& a , const fvector& b ) { return !( a == b ); }

			double vector_scalar( const fvector& v ) const { return x * v.x + y * v.y + z * v.z; }
			float distance_to( fvector v ) const { return double( sqrtf( powf( v.x - x , 2.0 ) + powf( v.y - y , 2.0 ) + powf( v.z - z , 2.0 ) ) ) / 100; }
			double distance( fvector v ) const { return double( sqrtf( powf( v.x - x , 2.0 ) + powf( v.y - y , 2.0 ) + powf( v.z - z , 2.0 ) ) ); }
			void in_validate( ) { this->x = this->y = this->z = std::numeric_limits<float>::infinity( ); }
			double length( ) const { return sqrt( x * x + y * y + z * z ); }

			float size_squared( ) const {
				return x * x + y * y + z * z;
			}

			double x , y , z;
		};

		struct fvector2d
		{
			fvector2d( ) : x( ) , y( ) { }
			fvector2d( double x , double y ) : x( x ) , y( y ) { }

			fvector2d operator + ( const fvector2d& other ) const { return { this->x + other.x, this->y + other.y }; }
			fvector2d operator - ( const fvector2d& other ) const { return { this->x - other.x, this->y - other.y }; }
			fvector2d operator * ( double offset ) const { return { this->x * offset, this->y * offset }; }
			fvector2d operator / ( double offset ) const { return { this->x / offset, this->y / offset }; }

			fvector2d& operator *= ( const double other ) { this->x *= other; this->y *= other; return *this; }
			fvector2d& operator /= ( const double other ) { this->x /= other; this->y /= other; return *this; }

			fvector2d& operator = ( const fvector2d& other ) { this->x = other.x; this->y = other.y; return *this; }
			fvector2d& operator += ( const fvector2d& other ) { this->x += other.x; this->y += other.y; return *this; }
			fvector2d& operator -= ( const fvector2d& other ) { this->x -= other.x; this->y -= other.y; return *this; }
			fvector2d& operator *= ( const fvector2d& other ) { this->x *= other.x; this->y *= other.y; return *this; }
			fvector2d& operator /= ( const fvector2d& other ) { this->x /= other.x; this->y /= other.y; return *this; }

			operator bool( ) { return bool( this->x || this->y ); }
			friend bool operator == ( const fvector2d& A , const fvector2d& B ) { return A.x == B.x && A.y == A.y; }
			friend bool operator != ( const fvector2d& A , const fvector2d& B ) { return !( A == B ); }

			double vector_scalar( const fvector2d& V ) const { return x * V.x + y * V.y; }
			double distance( fvector2d V ) const { return double( sqrtf( powf( V.x - this->x , 2.0 ) + powf( V.y - this->y , 2.0 ) ) ); }

			double x , y;
		};

		class frotator
		{
		public:
			frotator( ) : pitch( ) , yaw( ) , roll( ) { }
			frotator( double pitch , double yaw , double roll ) : pitch( pitch ) , yaw( yaw ) , roll( roll ) { }

			frotator operator + ( const frotator& other ) const { return { this->pitch + other.pitch, this->yaw + other.yaw, this->roll + other.roll }; }
			frotator operator - ( const frotator& other ) const { return { this->pitch - other.pitch, this->yaw - other.yaw, this->roll - other.roll }; }
			frotator operator * ( double offset ) const { return { this->pitch * offset, this->yaw * offset, this->roll * offset }; }
			frotator operator / ( double offset ) const { return { this->pitch / offset, this->yaw / offset, this->roll / offset }; }

			frotator& operator *= ( const double other ) { this->pitch *= other; this->yaw *= other; this->roll *= other; return *this; }
			frotator& operator /= ( const double other ) { this->pitch /= other; this->yaw /= other; this->roll /= other; return *this; }

			frotator& operator = ( const frotator& other ) { this->pitch = other.pitch; this->yaw = other.yaw; this->roll = other.roll; return *this; }
			frotator& operator += ( const frotator& other ) { this->pitch += other.pitch; this->yaw += other.yaw; this->roll += other.roll; return *this; }
			frotator& operator -= ( const frotator& other ) { this->pitch -= other.pitch; this->yaw -= other.yaw; this->roll -= other.roll; return *this; }
			frotator& operator *= ( const frotator& other ) { this->pitch *= other.pitch; this->yaw *= other.yaw; this->roll *= other.roll; return *this; }
			frotator& operator /= ( const frotator& other ) { this->pitch /= other.pitch; this->yaw /= other.yaw; this->roll /= other.roll; return *this; }

			operator bool( ) { return std::isfinite( this->pitch ) && std::isfinite( this->yaw ) && std::isfinite( this->roll ); }
			friend bool operator == ( const frotator& a , const frotator& b ) { return a.pitch == b.pitch && a.yaw == b.yaw && a.roll == b.roll; }
			friend bool operator != ( const frotator& a , const frotator& b ) { return !( a == b ); }

			frotator normalize( ) 
			{
				if ( *this ) 
				{
					this->pitch = std::clamp( this->pitch , -89.0 , 89.0 );
					this->yaw = std::clamp( this->yaw , -180.0 , 180.0 );
					this->roll = 0.0;
					return *this;
				}
			}

			double length( ) const { return sqrt( pitch * pitch + yaw * yaw + roll * roll ); }
			double dot( const frotator& a ) { return pitch * a.pitch + yaw * a.yaw + roll * a.roll; }
			double distance( const frotator& a ) { return double( sqrtf( powf( a.pitch - this->pitch , 2.0 ) + powf( a.yaw - this->yaw , 2.0 ) + powf( a.roll - this->roll , 2.0 ) ) ); }

			double pitch;
			double yaw;
			double roll;
		};

		struct f_plane : fvector {

			f_plane( ) : w( 0 ) { }
			f_plane( double w ) : w( w ) { }

			fvector to_vector( ) {
				fvector value;
				value.x = this->x;
				value.y = this->y;
				value.z = this->z;
				return value;
			}

			double w;
		};

		class c_matrix {
		public:
			double m[ 4 ][ 4 ];
			f_plane x_plane , y_plane , z_plane , w_plane;

			c_matrix( ) : x_plane( ) , y_plane( ) , z_plane( ) , w_plane( ) { }
			c_matrix( f_plane x_plane , f_plane y_plane , f_plane z_plane , f_plane w_plane )
				: x_plane( x_plane ) , y_plane( y_plane ) , z_plane( z_plane ) , w_plane( w_plane ) { }

			c_matrix to_multiplication( c_matrix m_matrix ) {

				c_matrix matrix{};

				matrix.w_plane.x = (
					this->w_plane.x * m_matrix.x_plane.x +
					this->w_plane.y * m_matrix.y_plane.x +
					this->w_plane.z * m_matrix.z_plane.x +
					this->w_plane.w * m_matrix.w_plane.x
					);

				matrix.w_plane.y = (
					this->w_plane.x * m_matrix.x_plane.y +
					this->w_plane.y * m_matrix.y_plane.y +
					this->w_plane.z * m_matrix.z_plane.y +
					this->w_plane.w * m_matrix.w_plane.y
					);

				matrix.w_plane.z = (
					this->w_plane.x * m_matrix.x_plane.z +
					this->w_plane.y * m_matrix.y_plane.z +
					this->w_plane.z * m_matrix.z_plane.z +
					this->w_plane.w * m_matrix.w_plane.z
					);

				matrix.w_plane.w = (
					this->w_plane.x * m_matrix.x_plane.w +
					this->w_plane.y * m_matrix.y_plane.w +
					this->w_plane.z * m_matrix.z_plane.w +
					this->w_plane.w * m_matrix.w_plane.w
					);

				return matrix;
			}

			c_matrix to_rotation_matrix( frotator& rotation )
			{
				c_matrix matrix = {};

				auto rad_pitch = ( rotation.pitch * std::numbers::pi / 180.f );
				auto rad_yaw = ( rotation.yaw * std::numbers::pi / 180.f );
				auto rad_roll = ( rotation.roll * std::numbers::pi / 180.f );

				auto sin_pitch = sin( rad_pitch );
				auto cos_pitch = cos( rad_pitch );

				auto sin_yaw = sin( rad_yaw );
				auto cos_yaw = cos( rad_yaw );

				auto sin_roll = sin( rad_roll );
				auto cos_roll = cos( rad_roll );

				matrix.x_plane.x = cos_pitch * cos_yaw;
				matrix.x_plane.y = cos_pitch * sin_yaw;
				matrix.x_plane.z = sin_pitch;
				matrix.x_plane.w = 0.f;

				matrix.y_plane.x = sin_roll * sin_pitch * cos_yaw - cos_roll * sin_yaw;
				matrix.y_plane.y = sin_roll * sin_pitch * sin_yaw + cos_roll * cos_yaw;
				matrix.y_plane.z = -sin_roll * cos_pitch;
				matrix.y_plane.w = 0.f;

				matrix.z_plane.x = -( cos_roll * sin_pitch * cos_yaw + sin_roll * sin_yaw );
				matrix.z_plane.y = cos_yaw * sin_roll - cos_roll * sin_pitch * sin_yaw;
				matrix.z_plane.z = cos_roll * cos_pitch;
				matrix.z_plane.w = 0.f;

				matrix.w_plane.w = 1.f;

				return matrix;
			}
		};

		class ftransform {
		public:

			f_plane rotation;
			fvector translation;
			char pad[ 0x4 ]; // 0x38(0x08)
			fvector scale;
			char pad1[ 0x4 ]; // 0x58(0x08)

			ftransform( ) : rotation( ) , translation( 0.f , 0.f , 0.f ) , scale( 0.f , 0.f , 0.f ) , pad( ) , pad1( ) { }

			ftransform( const f_plane& rot , const fvector& translation , const fvector& scale )
			{
				this->rotation = rot;
				this->translation = translation;

				this->pad[ 0x4 ] = 0;
				this->scale = scale;
				this->pad1[ 0x4 ] = 0;
			}

			c_matrix to_matrix( )
			{
				c_matrix matrix = {};

				auto x2 = this->rotation.x * 2;
				auto y2 = this->rotation.y * 2;
				auto z2 = this->rotation.z * 2;

				auto xx2 = this->rotation.x * x2;
				auto yy2 = this->rotation.y * y2;
				auto zz2 = this->rotation.z * z2;

				auto yz2 = this->rotation.y * z2;
				auto wx2 = this->rotation.w * x2;

				auto xy2 = this->rotation.x * y2;
				auto wz2 = this->rotation.w * z2;

				auto xz2 = this->rotation.x * z2;
				auto wy2 = this->rotation.w * y2;

				matrix.x_plane.x = ( 1.0 - ( yy2 + zz2 ) ) * this->scale.x;
				matrix.x_plane.y = ( xy2 + wz2 ) * this->scale.x;
				matrix.x_plane.z = ( xz2 - wy2 ) * this->scale.x;

				matrix.y_plane.x = ( xy2 - wz2 ) * this->scale.y;
				matrix.y_plane.y = ( 1.0 - ( xx2 + zz2 ) ) * this->scale.y;
				matrix.y_plane.z = ( yz2 + wx2 ) * this->scale.y;

				matrix.z_plane.x = ( xz2 + wy2 ) * this->scale.z;
				matrix.z_plane.y = ( yz2 - wx2 ) * this->scale.z;
				matrix.z_plane.z = ( 1.0 - ( xx2 + yy2 ) ) * this->scale.z;

				matrix.w_plane.x = this->translation.x;
				matrix.w_plane.y = this->translation.y;
				matrix.w_plane.z = this->translation.z;

				matrix.w_plane.w = 1.0;

				return matrix;
			}
		};

		struct flinearcolor
		{
			flinearcolor( ) : a( ) , r( ) , g( ) , b( ) { }
			flinearcolor( int8_t a , int8_t r , int8_t g , int8_t b ) : a( a ) , r( r ) , g( g ) , b( b ) { }

			int8_t a , r , g , b;
		};

		struct fbox_sphere_bounds final
		{
		public:
			struct fvector                        orgin;                                            // 0x0000(0x0018)(Edit, BlueprintVisible, ZeroConstructor, SaveGame, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
			struct fvector                        box_extent;                                         // 0x0018(0x0018)(Edit, BlueprintVisible, ZeroConstructor, SaveGame, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
			double                                        sphere_radius;                                      // 0x0030(0x0008)(Edit, BlueprintVisible, ZeroConstructor, SaveGame, IsPlainOldData, NoDestructor, HasGetValueTypeHash, NativeAccessSpecifierPublic)
		};
	}
}