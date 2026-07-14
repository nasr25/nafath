<?php

namespace Database\Seeders;

use Illuminate\Database\Seeder;
use Illuminate\Support\Facades\DB;

class DatabaseSeeder extends Seeder
{
    /**
     * Seed the application's database.
     */
    public function run(): void
    {
        // The single user from test.php. `id_number` is set to the National Id
        // used in the NAFATH guide's sample Id_token (sub = 1132077577) so the
        // callback comparison finds this record out of the box — change it to a
        // real National Id for live testing.
        DB::table('users')->updateOrInsert(
            ['id' => 1],
            [
                'first_name'          => 'Test',
                'middle_name'         => 'User',
                'last_name'           => '',
                'email'               => 'user@example.com',
                'phone_code'          => '+966',
                'phone'               => '555555555',
                'phone_code_id'       => 1,
                'country_code'        => null,
                'avatar'              => null,
                'otp'                 => null,
                'password'            => '$2y$12$hvwmqSCwSI7Kw0x3aPfHLOX/G3IMyH.RMcZfJ9HWLWisp/tUydWiO',
                'gender'              => 'male',
                'id_number'           => '1132077577',
                'date_of_birth'       => null,
                'is_military'         => 0,
                'military_number'     => null,
                'is_military_updated' => 1,
                'max_request_number'  => null,
                'terms_condition_id'  => null,
                'id_type_id'          => null,
                'nationality_id'      => null,
                'created_by'          => null,
                'is_active'           => 1,
                'preferred_language'  => 'en',
                'last_login'          => null,
                'remember_token'      => null,
                'email_verified_at'   => null,
                'created_at'          => '2025-05-27 13:51:19',
                'updated_at'          => '2025-05-27 13:51:20',
                'deleted_at'          => null,
            ]
        );
    }
}
