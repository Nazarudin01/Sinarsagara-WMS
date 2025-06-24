'use client';

import { Fragment, useState } from 'react';
import { Combobox as HeadlessCombobox, Transition } from '@headlessui/react';
import { CheckIcon, ChevronUpDownIcon } from '@heroicons/react/20/solid';
import ReactDOM from 'react-dom';

interface Option {
  id: string;
  name: string;
}

interface ComboboxProps {
  options: Option[];
  value: Option | null;
  onChange: (value: Option) => void;
  placeholder?: string;
  label?: string;
  onAddNew?: (name: string) => void;
  labelAddNew?: string;
}

export default function Combobox({
  options,
  value,
  onChange,
  placeholder = 'Pilih...',
  label,
  onAddNew,
  labelAddNew = '+ Tambah Baru',
}: ComboboxProps) {
  const [query, setQuery] = useState('');
  const [showAddInput, setShowAddInput] = useState(false);
  const [newValue, setNewValue] = useState('');

  const filteredOptions =
    query === ''
      ? options
      : options.filter((option) =>
          option.name
            .toLowerCase()
            .replace(/\s+/g, '')
            .includes(query.toLowerCase().replace(/\s+/g, ''))
        );

  return (
    <div className="w-full">
      {label && (
        <label className="block text-sm font-medium text-gray-700 dark:text-gray-200 mb-1">
          {label}
        </label>
      )}
      <HeadlessCombobox value={value} onChange={onChange}>
        <div className="relative">
          <div className="relative w-full cursor-default overflow-hidden rounded-lg bg-white text-left border border-gray-300 focus:outline-none focus-visible:ring-2 focus-visible:ring-white focus-visible:ring-opacity-75 focus-visible:ring-offset-2 focus-visible:ring-offset-indigo-300 sm:text-sm">
            <HeadlessCombobox.Input
              className="w-full border-none py-2 pl-3 pr-10 text-sm leading-5 text-gray-900 dark:text-white focus:ring-0"
              displayValue={(option: Option) => option?.name}
              onChange={(event) => setQuery(event.target.value)}
              placeholder={placeholder}
            />
            <HeadlessCombobox.Button className="absolute inset-y-0 right-0 flex items-center pr-2">
              <ChevronUpDownIcon
                className="h-5 w-5 text-gray-400"
                aria-hidden="true"
              />
            </HeadlessCombobox.Button>
          </div>
          <Transition
            as="div"
            leave="transition ease-in duration-100"
            leaveFrom="opacity-100"
            leaveTo="opacity-0"
            afterLeave={() => { setQuery(''); setShowAddInput(false); setNewValue(''); }}
          >
            <HeadlessCombobox.Options className="absolute z-50 mt-1 left-0 min-w-[200px] max-w-[400px] overflow-auto rounded-md bg-white dark:bg-gray-800 py-1 text-base shadow-lg ring-1 ring-black ring-opacity-5 focus:outline-none sm:text-sm">
              {filteredOptions.length === 0 && query !== '' ? (
                <div className="relative cursor-default select-none py-2 px-4 text-gray-700">
                  Tidak ditemukan.
                </div>
              ) : (
                filteredOptions.map((option) => (
                  <HeadlessCombobox.Option
                    key={option.id}
                    className={({ active }) =>
                      `relative cursor-default select-none py-2 pl-10 pr-4 ${
                        active
                          ? 'bg-indigo-600 text-white dark:text-black'
                          : 'text-gray-900 dark:text-white'
                      }`
                    }
                    value={option}
                  >
                    {({ selected, active }) => (
                      <>
                        <span
                          className={`block truncate ${
                            selected ? 'font-medium' : 'font-normal'
                          }`}
                        >
                          {option.name}
                        </span>
                        {selected ? (
                          <span
                            className={`absolute inset-y-0 left-0 flex items-center pl-3 ${
                              active ? 'text-white' : 'text-indigo-600'
                            }`}
                          >
                            <CheckIcon className="h-5 w-5" aria-hidden="true" />
                          </span>
                        ) : null}
                      </>
                    )}
                  </HeadlessCombobox.Option>
                ))
              )}
              {onAddNew && !showAddInput && (
                <div
                  className="relative cursor-pointer select-none py-2 px-4 text-indigo-600 hover:bg-indigo-50 border-t border-gray-100"
                  onClick={e => {
                    e.stopPropagation();
                    setShowAddInput(true);
                    setNewValue(query);
                  }}
                >
                  {labelAddNew} {query && `"${query}"`}
                </div>
              )}
              {onAddNew && showAddInput && (
                <div className="flex items-center gap-2 py-2 px-4 border-t border-gray-100 bg-white dark:bg-gray-900 p-2 rounded shadow">
                  <input
                    className="border rounded px-2 py-1 text-sm flex-1 text-gray-900 dark:text-white bg-white dark:bg-gray-900"
                    value={newValue}
                    onChange={e => setNewValue(e.target.value)}
                    placeholder="Nama baru"
                    autoFocus
                  />
                  <button
                    className="text-indigo-700 font-bold text-xs px-2 py-1 border border-indigo-400 rounded hover:bg-indigo-100"
                    type="button"
                    onClick={() => {
                      if (newValue.trim()) {
                        onAddNew(newValue.trim());
                        setShowAddInput(false);
                        setNewValue('');
                      }
                    }}
                  >Tambah</button>
                  <button
                    className="text-gray-400 text-xs px-2 py-1"
                    type="button"
                    onClick={() => { setShowAddInput(false); setNewValue(''); }}
                  >Batal</button>
                </div>
              )}
            </HeadlessCombobox.Options>
          </Transition>
        </div>
      </HeadlessCombobox>
    </div>
  );
} 