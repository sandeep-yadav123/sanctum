<?php

namespace App\Http\Controllers;

use Illuminate\Http\Request;
use App\Models\User;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Auth; 
use Laravel\Sanctum\PersonalAccessToken;

use Validator;

class UserController extends Controller
{
	/** 
	* login api 
	* 
	* @return \Illuminate\Http\Response 
	*/
	public function login(Request $request)
	{
	    $user= User::where('email', $request->email)->first();

        if (!$user || !Hash::check($request->password, $user->password)) {
            return response([
                'message' => ['These credentials do not match our records.']
            ], 404);
        }
	    
	    $token = $user->createToken('MyApp')->plainTextToken;
	    
        $response = [
            'user' => $user,
            'token' => $token
        ];
	    return response($response, 201);
	}
	/** 
	* Register api 
	* 
	* @return \Illuminate\Http\Response 
	*/ 
	public function register(Request $request) 
	{ 
		$validator = Validator::make($request->all(), [ 
			'name' => 'required', 
			'email' => 'required|email', 
			'password' => 'required', 
			'c_password' => 'required|same:password', 
		]);

		if ($validator->fails()) { 
			return response()->json(['error'=>$validator->errors()], 401);            
		}

		$input = $request->all(); 

		$input['password'] = Hash::make($input['password']); 
		$user = User::create($input); 
		$success['token'] = $user->createToken('MyApp')->plainTextToken;
		$success['name'] =  $user->name;
		return response()->json(['success'=>$success], 200); 
	}
	/** 
	* details api 
	* 
	* @return \Illuminate\Http\Response 
	*/ 
    public function details() 
    { 
        $user = Auth::user(); 
        return response()->json(['success' => $user], 200); 
    }

	public function logout(Request $request)
    {
    	//auth()->user()->tokens()->delete();
    	$request->user()->currentAccessToken()->delete();
        return [
            'message' => 'Tokens Revoked'
        ];
    }

}
