import React, { useContext, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import assets from '../assets/assets';
import { AuthContext } from '../../context/AuthContext';

const ProfilePage = () => {
  const { authUser, updateProfile } = useContext(AuthContext);
  const navigate = useNavigate();

  const [selectedImg, setSelectedImg] = useState(null);
  const [name, setName] = useState(authUser.fullName);
  const [bio, setBio] = useState(authUser.bio);

  const handleSubmit = async (e) => {
    e.preventDefault();

    // If no new image is selected, update only text
    if (!selectedImg) {
      await updateProfile({ fullName: name, bio });
      navigate('/');
      return;
    }

    // Convert image to base64
    const reader = new FileReader();
    reader.readAsDataURL(selectedImg);
    reader.onload = async () => {
      const base64Image = reader.result;
      await updateProfile({ profilePic: base64Image, fullName: name, bio });
      navigate('/');
    };
  };

  return (
    <div className='min-h-screen bg-cover bg-no-repeat flex items-center justify-center'>
      <div className='w-5/6 max-w-2xl backdrop-blur-2xl text-gray-300 border-2 border-gray-600 flex items-center justify-center max-sm:flex-col-reverse rounded-lg'>

        {/* === Form Section === */}
        <form onSubmit={handleSubmit} className='flex flex-col gap-5 p-10 flex-1'>
          <h3 className='text-lg'>Profile Details</h3>

          {/* === Image Upload === */}
          <label htmlFor='avatar' className='flex items-center gap-3 cursor-pointer'>
            <input
              onChange={(e) => setSelectedImg(e.target.files[0])}
              type="file"
              id='avatar'
              accept='.png, .jpg, .jpeg'
              hidden
            />
            <img
              src={
                selectedImg
                  ? URL.createObjectURL(selectedImg)
                  : authUser.profilePic || assets.avatar_icon
              }
              alt="avatar"
              className='w-12 h-12 object-cover rounded-full'
            />
            Upload profile image
          </label>

          {/* === Name Field === */}
          <input
            onChange={(e) => setName(e.target.value)}
            value={name}
            type="text"
            required
            placeholder='Your Name'
            className='p-2 border border-gray-500 rounded-md focus:outline-none focus:ring-2 focus:ring-violet-500'
          />

          {/* === Bio Field === */}
          <textarea
            onChange={(e) => setBio(e.target.value)}
            value={bio}
            placeholder='Write profile bio'
            required
            className='p-2 border border-gray-500 rounded-md focus:outline-none focus:ring-2 focus:ring-violet-500'
            rows={4}
          />

          {/* === Submit Button === */}
          <button
            type='submit'
            className='bg-gradient-to-r from-purple-400 to-violet-600 text-white p-2 rounded-full text-lg cursor-pointer'
          >
            Save
          </button>
        </form>

        {/* === Right-side Display Image === */}
        <img
          className='max-w-44 aspect-square rounded-full object-cover mx-10 max-sm:mt-10'
          src={
            selectedImg
              ? URL.createObjectURL(selectedImg)
              : authUser.profilePic || assets.logo_icon
          }
          alt="profile preview"
        />
      </div>
    </div>
  );
};

export default ProfilePage;
