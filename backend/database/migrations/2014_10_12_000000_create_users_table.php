<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration
{
    /**
     * Run the migrations.
     *
     * Mirrors the production `users` schema (from test.php). The cross-table
     * FOREIGN KEY constraints (admins, countries, id_types, terms_conditions)
     * are intentionally NOT declared here so this migration runs standalone in
     * this Nafath demo DB. Re-add them via a follow-up migration if you run it
     * against the full production schema where those tables exist.
     */
    public function up(): void
    {
        Schema::create('users', function (Blueprint $table) {
            $table->id();
            $table->string('first_name');
            $table->string('middle_name')->nullable();
            $table->string('last_name')->nullable();
            $table->string('email');
            $table->string('phone_code')->nullable();
            $table->string('phone')->nullable();
            $table->unsignedBigInteger('phone_code_id')->nullable();
            $table->string('country_code')->nullable();
            $table->string('avatar')->nullable();
            $table->string('otp')->nullable();
            $table->string('password')->nullable();
            $table->string('gender')->nullable();
            $table->string('id_number')->nullable();
            $table->date('date_of_birth')->nullable();
            $table->tinyInteger('is_military')->default(0);
            $table->string('military_number')->nullable();
            $table->boolean('is_military_updated')->default(true);
            $table->integer('max_request_number')->nullable();
            $table->unsignedBigInteger('terms_condition_id')->nullable();
            $table->unsignedBigInteger('id_type_id')->nullable();
            $table->unsignedBigInteger('nationality_id')->nullable();
            $table->unsignedBigInteger('created_by')->nullable();
            $table->boolean('is_active')->default(true);
            $table->string('preferred_language')->default('en');
            $table->timestamp('last_login')->nullable();
            $table->rememberToken();
            $table->timestamp('email_verified_at')->nullable();
            $table->timestamps();
            $table->softDeletes();

            // Indexes kept from the original schema (FK constraints omitted).
            $table->index('terms_condition_id', 'users_terms_condition_id_foreign');
            $table->index('id_type_id', 'users_id_type_id_foreign');
            $table->index('nationality_id', 'users_nationality_id_foreign');
            $table->index('created_by', 'users_created_by_foreign');
            $table->index('phone_code_id', 'users_phone_code_id_foreign');

            // Nafath matches users by their National / Iqama Id (the `sub` claim).
            $table->index('id_number', 'users_id_number_index');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('users');
    }
};
