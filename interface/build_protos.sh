pushd public
for file_name_and_ext in $(ls *.proto)
do
    file_name=`echo $file_name_and_ext | cut -d'.' -f1`
    protoc -o$file_name.pb $file_name_and_ext
    python $NANOPB_PATH/nanopb_generator.py $file_name.pb
done
mv *.pb.c ../local
popd

